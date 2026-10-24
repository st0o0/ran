package trap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"strings"
	"time"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// Limits for client-controlled MongoDB sizes. The wire protocol allows 48 MB per
// message; a sensor only needs the handshake and the first command, so messages
// above 64 KiB close the connection before anything is allocated for them.
const (
	maxMongoMessage = 64 << 10
	mongoHeaderLen  = 16
	// maxBSONElements bounds how many top-level elements of a document are
	// walked. Nested documents and arrays are skipped by their declared length,
	// never entered, so the walk has no recursion depth.
	maxBSONElements = 64
	// maxMongoNamespace bounds the collection name of a legacy OP_QUERY.
	maxMongoNamespace = 256
	// maxMongoAuthField bounds the user name taken from an authentication command.
	maxMongoAuthField = 128
	// maxMongoSASLPayload bounds how much of a SASL payload is looked at.
	maxMongoSASLPayload = 1024
)

// MongoDB opcodes handled by the trap.
const (
	mongoOpReply = 1
	mongoOpQuery = 2004
	mongoOpMsg   = 2013
)

// OP_MSG flag bits.
const (
	mongoMsgChecksum   = 1 << 0
	mongoMsgMoreToCome = 1 << 1
)

var (
	errMongoLength      = fmt.Errorf("mongodb message length out of range: %w", bufio.ErrTooLong)
	errMongoMalformed   = errors.New("malformed mongodb message")
	errMongoUnsupported = errors.New("unsupported mongodb opcode")
)

type MongoDBTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	now     func() time.Time
}

func NewMongoDB(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *MongoDBTrap {
	t := &MongoDBTrap{cfg: cfg, logger: logger, metrics: m, now: time.Now}
	t.tcpServer = newTCPServer("mongodb", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

type mongoHeader struct {
	length     int
	requestID  int32
	responseTo int32
	opCode     int32
}

// readMongoMessage reads one message. The declared length is checked against
// maxMongoMessage before anything is read, and the body is collected with a
// limited reader, so memory follows the bytes that actually arrive.
func readMongoMessage(r io.Reader) (mongoHeader, []byte, error) {
	var hdr [mongoHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return mongoHeader{}, nil, err
	}
	n, ok := fitsInt(binary.LittleEndian.Uint32(hdr[0:4]), math.MaxInt)
	if !ok || n > maxMongoMessage {
		return mongoHeader{}, nil, errMongoLength
	}
	if n < mongoHeaderLen {
		return mongoHeader{}, nil, errMongoMalformed
	}
	h := mongoHeader{
		length:     n,
		requestID:  int32(binary.LittleEndian.Uint32(hdr[4:8])),
		responseTo: int32(binary.LittleEndian.Uint32(hdr[8:12])),
		opCode:     int32(binary.LittleEndian.Uint32(hdr[12:16])),
	}
	body, err := io.ReadAll(io.LimitReader(r, int64(n-mongoHeaderLen)))
	if err != nil {
		return h, nil, err
	}
	if len(body) != n-mongoHeaderLen {
		return h, nil, io.ErrUnexpectedEOF
	}
	return h, body, nil
}

// --- BSON reading (bounded, top level only) ---

type bsonElem struct {
	typ byte
	key string
	val []byte
}

func fixedBSON(n int, rest []byte) (int, error) {
	if len(rest) < n {
		return 0, errMongoMalformed
	}
	return n, nil
}

// bsonValueSize returns the encoded size of a value of type typ at the start of
// rest. Comparisons are written against len(rest) so that no addition can
// overflow a 32-bit int.
func bsonValueSize(typ byte, rest []byte) (int, error) {
	switch typ {
	case 0x01, 0x09, 0x11, 0x12:
		return fixedBSON(8, rest)
	case 0x10:
		return fixedBSON(4, rest)
	case 0x07:
		return fixedBSON(12, rest)
	case 0x08:
		return fixedBSON(1, rest)
	case 0x13:
		return fixedBSON(16, rest)
	case 0x06, 0x0A, 0x7F, 0xFF:
		return 0, nil
	case 0x02, 0x0D, 0x0E:
		if len(rest) < 4 {
			return 0, errMongoMalformed
		}
		n, ok := fitsInt(binary.LittleEndian.Uint32(rest), math.MaxInt)
		if !ok || n < 1 || n > len(rest)-4 {
			return 0, errMongoMalformed
		}
		return 4 + n, nil
	case 0x03, 0x04, 0x0F:
		if len(rest) < 4 {
			return 0, errMongoMalformed
		}
		n, ok := fitsInt(binary.LittleEndian.Uint32(rest), math.MaxInt)
		if !ok || n < 5 || n > len(rest) {
			return 0, errMongoMalformed
		}
		return n, nil
	case 0x05:
		if len(rest) < 5 {
			return 0, errMongoMalformed
		}
		n, ok := fitsInt(binary.LittleEndian.Uint32(rest), math.MaxInt)
		if !ok || n > len(rest)-5 {
			return 0, errMongoMalformed
		}
		return 5 + n, nil
	case 0x0B:
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			return 0, errMongoMalformed
		}
		j := bytes.IndexByte(rest[i+1:], 0)
		if j < 0 {
			return 0, errMongoMalformed
		}
		return i + 1 + j + 1, nil
	case 0x0C:
		if len(rest) < 4 {
			return 0, errMongoMalformed
		}
		n, ok := fitsInt(binary.LittleEndian.Uint32(rest), math.MaxInt)
		if !ok || n < 1 || n > len(rest)-16 {
			return 0, errMongoMalformed
		}
		return 4 + n + 12, nil
	}
	return 0, errMongoMalformed
}

// bsonWalk calls fn for the first maxBSONElements top-level elements of doc until
// fn returns false. The declared document length must fit the data.
func bsonWalk(doc []byte, fn func(e bsonElem) bool) error {
	if len(doc) < 5 {
		return errMongoMalformed
	}
	n, ok := fitsInt(binary.LittleEndian.Uint32(doc), math.MaxInt)
	if !ok || n < 5 || n > len(doc) || doc[n-1] != 0 {
		return errMongoMalformed
	}
	body := doc[:n-1]
	pos := 4
	for count := 0; pos < len(body) && count < maxBSONElements; count++ {
		typ := body[pos]
		pos++
		end := bytes.IndexByte(body[pos:], 0)
		if end < 0 {
			return errMongoMalformed
		}
		key := string(body[pos : pos+end])
		pos += end + 1
		size, err := bsonValueSize(typ, body[pos:])
		if err != nil {
			return err
		}
		val := body[pos : pos+size]
		pos += size
		if !fn(bsonElem{typ: typ, key: key, val: val}) {
			return nil
		}
	}
	return nil
}

// bsonString decodes a string value (its length was validated by bsonValueSize).
func bsonString(e bsonElem) (string, bool) {
	if e.typ != 0x02 || len(e.val) < 5 {
		return "", false
	}
	return string(e.val[4 : len(e.val)-1]), true
}

// bsonBinary decodes the data of a binary value; a string value is accepted too.
func bsonBinary(e bsonElem) ([]byte, bool) {
	switch e.typ {
	case 0x05:
		if len(e.val) < 5 {
			return nil, false
		}
		return e.val[5:], true
	case 0x02:
		s, ok := bsonString(e)
		return []byte(s), ok
	}
	return nil, false
}

// --- request parsing ---

type mongoRequest struct {
	opCode    int32
	command   string
	db        string
	mechanism string
	user      string
	payload   []byte
	noReply   bool
}

// parseMongoMessage extracts the command from an OP_MSG or OP_QUERY body. Other
// opcodes return errMongoUnsupported. A legacy OP_QUERY that is not a command
// (the collection does not end in .$cmd) yields the command "query".
func parseMongoMessage(h mongoHeader, body []byte) (mongoRequest, error) {
	req := mongoRequest{opCode: h.opCode}
	var doc []byte
	switch h.opCode {
	case mongoOpMsg:
		if len(body) < 4 {
			return req, errMongoMalformed
		}
		flags := binary.LittleEndian.Uint32(body)
		// Unknown required bits (0-15) make the message invalid.
		if flags&0xFFFF&^(mongoMsgChecksum|mongoMsgMoreToCome) != 0 {
			return req, errMongoMalformed
		}
		req.noReply = flags&mongoMsgMoreToCome != 0
		rest := body[4:]
		if flags&mongoMsgChecksum != 0 {
			if len(rest) < 4 {
				return req, errMongoMalformed
			}
			rest = rest[:len(rest)-4]
		}
		for len(rest) > 0 && doc == nil {
			kind := rest[0]
			rest = rest[1:]
			if len(rest) < 4 {
				return req, errMongoMalformed
			}
			size, ok := fitsInt(binary.LittleEndian.Uint32(rest), math.MaxInt)
			if !ok || size < 4 || size > len(rest) {
				return req, errMongoMalformed
			}
			switch kind {
			case 0:
				doc = rest[:size]
			case 1:
				// Document sequence: skipped, only the command document counts.
			default:
				return req, errMongoMalformed
			}
			rest = rest[size:]
		}
		if doc == nil {
			return req, errMongoMalformed
		}
	case mongoOpQuery:
		if len(body) < 4 {
			return req, errMongoMalformed
		}
		rest := body[4:]
		i := bytes.IndexByte(rest, 0)
		if i < 0 || i > maxMongoNamespace {
			return req, errMongoMalformed
		}
		ns := string(rest[:i])
		rest = rest[i+1:]
		if len(rest) < 8 {
			return req, errMongoMalformed
		}
		doc = rest[8:]
		db, ok := strings.CutSuffix(ns, ".$cmd")
		if !ok {
			req.command = "query"
			req.db, _, _ = strings.Cut(ns, ".")
			return req, nil
		}
		req.db = db
	default:
		return req, errMongoUnsupported
	}

	first := true
	err := bsonWalk(doc, func(e bsonElem) bool {
		if first {
			first = false
			req.command = e.key
			return true
		}
		switch e.key {
		case "$db":
			if s, ok := bsonString(e); ok {
				req.db = s
			}
		case "mechanism":
			if s, ok := bsonString(e); ok {
				req.mechanism = s
			}
		case "user":
			if s, ok := bsonString(e); ok {
				req.user = s
			}
		case "payload":
			if b, ok := bsonBinary(e); ok {
				req.payload = b
			}
		}
		return true
	})
	if err != nil {
		return req, err
	}
	if first {
		return req, errMongoMalformed
	}
	return req, nil
}

// mongoSASLUser returns the user name from a SASL payload: the authcid of PLAIN
// or the n= attribute of a SCRAM client-first message. The rest of the payload
// (password, nonce, proof) is never returned.
func mongoSASLUser(payload []byte) string {
	if len(payload) > maxMongoSASLPayload {
		payload = payload[:maxMongoSASLPayload]
	}
	if bytes.IndexByte(payload, 0) >= 0 {
		// Only the full form authzid NUL authcid NUL passwd is understood. Any
		// other shape is not guessed at: a two part payload would put the
		// password where a user name is expected.
		parts := bytes.Split(payload, []byte{0})
		if len(parts) == 3 {
			return string(parts[1])
		}
		return ""
	}
	for _, f := range strings.Split(string(payload), ",") {
		if u, ok := strings.CutPrefix(f, "n="); ok {
			return strings.NewReplacer("=2C", ",", "=3D", "=").Replace(u)
		}
	}
	return ""
}

// --- BSON writing ---

type bsonDoc struct{ b []byte }

func newBSONDoc() *bsonDoc { return &bsonDoc{b: make([]byte, 4)} }

func (d *bsonDoc) key(typ byte, k string) {
	d.b = append(d.b, typ)
	d.b = append(d.b, k...)
	d.b = append(d.b, 0)
}

func (d *bsonDoc) str(k, v string) *bsonDoc {
	d.key(0x02, k)
	d.b = binary.LittleEndian.AppendUint32(d.b, uint32(len(v)+1))
	d.b = append(d.b, v...)
	d.b = append(d.b, 0)
	return d
}

func (d *bsonDoc) i32(k string, v int32) *bsonDoc {
	d.key(0x10, k)
	d.b = binary.LittleEndian.AppendUint32(d.b, uint32(v))
	return d
}

func (d *bsonDoc) boolean(k string, v bool) *bsonDoc {
	d.key(0x08, k)
	if v {
		d.b = append(d.b, 1)
	} else {
		d.b = append(d.b, 0)
	}
	return d
}

func (d *bsonDoc) double(k string, v float64) *bsonDoc {
	d.key(0x01, k)
	d.b = binary.LittleEndian.AppendUint64(d.b, math.Float64bits(v))
	return d
}

func (d *bsonDoc) datetime(k string, t time.Time) *bsonDoc {
	d.key(0x09, k)
	d.b = binary.LittleEndian.AppendUint64(d.b, uint64(t.UnixMilli()))
	return d
}

func (d *bsonDoc) ints(k string, vs ...int32) *bsonDoc {
	arr := newBSONDoc()
	for i, v := range vs {
		arr.i32(fmt.Sprint(i), v)
	}
	d.key(0x04, k)
	d.b = append(d.b, arr.bytes()...)
	return d
}

func (d *bsonDoc) bytes() []byte {
	out := append(append([]byte(nil), d.b...), 0)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}

func mongoHelloDoc(now time.Time) []byte {
	return newBSONDoc().
		boolean("helloOk", true).
		boolean("ismaster", true).
		boolean("isWritablePrimary", true).
		i32("maxBsonObjectSize", 16777216).
		i32("maxMessageSizeBytes", 48000000).
		i32("maxWriteBatchSize", 100000).
		datetime("localTime", now).
		i32("logicalSessionTimeoutMinutes", 30).
		i32("connectionId", 1).
		i32("minWireVersion", 0).
		i32("maxWireVersion", 17).
		boolean("readOnly", false).
		double("ok", 1).bytes()
}

func mongoBuildInfoDoc() []byte {
	return newBSONDoc().
		str("version", "6.0.14").
		str("gitVersion", "e3dd2d2d5ee3ee0e1a2b5e3a6f7d3d3b1a1f2c3d").
		str("allocator", "tcmalloc").
		str("javascriptEngine", "mozjs").
		str("sysInfo", "deprecated").
		ints("versionArray", 6, 0, 14, 0).
		i32("bits", 64).
		boolean("debug", false).
		i32("maxBsonObjectSize", 16777216).
		double("ok", 1).bytes()
}

func mongoOKDoc() []byte { return newBSONDoc().double("ok", 1).bytes() }

func mongoErrorDoc(msg string, code int32, name string) []byte {
	return newBSONDoc().
		double("ok", 0).
		str("errmsg", msg).
		i32("code", code).
		str("codeName", name).bytes()
}

// mongoReply frames doc as a reply to the request: OP_MSG for OP_MSG, OP_REPLY
// for OP_QUERY.
func mongoReply(req mongoRequest, h mongoHeader, respID int32, doc []byte) []byte {
	var payload []byte
	op := int32(mongoOpMsg)
	if req.opCode == mongoOpQuery {
		op = mongoOpReply
		payload = binary.LittleEndian.AppendUint32(payload, 8) // AwaitCapable
		payload = binary.LittleEndian.AppendUint64(payload, 0) // cursor id
		payload = binary.LittleEndian.AppendUint32(payload, 0) // starting from
		payload = binary.LittleEndian.AppendUint32(payload, 1) // number returned
	} else {
		payload = binary.LittleEndian.AppendUint32(payload, 0) // flag bits
		payload = append(payload, 0)                           // section kind 0
	}
	payload = append(payload, doc...)
	out := make([]byte, 0, mongoHeaderLen+len(payload))
	out = binary.LittleEndian.AppendUint32(out, uint32(mongoHeaderLen+len(payload)))
	out = binary.LittleEndian.AppendUint32(out, uint32(respID))
	out = binary.LittleEndian.AppendUint32(out, uint32(h.requestID))
	out = binary.LittleEndian.AppendUint32(out, uint32(op))
	return append(out, payload...)
}

func (t *MongoDBTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	reader := bufio.NewReaderSize(conn, 4096)
	var respID int32

	for {
		h, body, err := readMongoMessage(reader)
		if err != nil {
			if err != io.EOF {
				sess.setReadOutcome(err)
			}
			return
		}
		req, err := parseMongoMessage(h, body)
		if errors.Is(err, errMongoUnsupported) {
			// A well-formed header with an opcode the trap does not speak: keep
			// the size as payload and drop the connection.
			sess.LogPayloadSize("mongodb_opcode", len(body), slog.Int("opcode", int(h.opCode)), slog.Int("bytes", len(body)))
			return
		}
		if err != nil {
			sess.SetOutcome(outcomeError)
			return
		}

		name := sanitizeHTTPValue(req.command)
		db := sanitizeHTTPValue(req.db)
		var doc []byte
		switch lower := strings.ToLower(req.command); lower {
		case "hello", "ismaster":
			sess.Log("mongodb handshake", slog.String("command", name), slog.String("db", db))
			doc = mongoHelloDoc(t.now())
		case "buildinfo":
			sess.Log("mongodb handshake", slog.String("command", name), slog.String("db", db))
			doc = mongoBuildInfoDoc()
		case "ping":
			sess.Log("mongodb handshake", slog.String("command", name), slog.String("db", db))
			doc = mongoOKDoc()
		case "saslstart", "authenticate":
			user := req.user
			if lower == "saslstart" {
				user = mongoSASLUser(req.payload)
			}
			user = truncateRunes(sanitizeHTTPValue(user), maxMongoAuthField)
			mech := truncateRunes(sanitizeHTTPValue(req.mechanism), maxCommandNameBytes)
			sess.LogAuthAttempt(slog.String("username", user), slog.String("mechanism", mech), slog.String("db", db))
			sess.RecordCredentials(t.metrics)
			sess.Alert(ctx, map[string]string{"username": user, "mechanism": mech})
			doc = mongoErrorDoc("Authentication failed.", 18, "AuthenticationFailed")
		default:
			sess.LogCommand(name, slog.String("db", db))
			sess.AlertCommand(ctx, name)
			doc = mongoErrorDoc("command "+commandName(name)+" requires authentication", 13, "Unauthorized")
		}

		if req.noReply {
			continue
		}
		respID++
		if _, err := conn.Write(mongoReply(req, h, respID, doc)); err != nil {
			setOutcome(sess, err)
			return
		}
	}
}
