package trap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func startMongoDB(t *testing.T) *stubHarness {
	return startStub(t, "mongodb", func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		return NewMongoDB(c, l, m, lim, r)
	})
}

// --- message builders ---

func mongoFrame(opCode int32, requestID int32, body []byte) []byte {
	out := make([]byte, 0, mongoHeaderLen+len(body))
	out = binary.LittleEndian.AppendUint32(out, uint32(mongoHeaderLen+len(body)))
	out = binary.LittleEndian.AppendUint32(out, uint32(requestID))
	out = binary.LittleEndian.AppendUint32(out, 0)
	out = binary.LittleEndian.AppendUint32(out, uint32(opCode))
	return append(out, body...)
}

func opMsg(doc []byte, flags uint32) []byte {
	body := binary.LittleEndian.AppendUint32(nil, flags)
	body = append(body, 0)
	body = append(body, doc...)
	return mongoFrame(mongoOpMsg, 7, body)
}

func opQuery(ns string, doc []byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, 0)
	body = append(body, ns...)
	body = append(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 0xFFFFFFFF)
	body = append(body, doc...)
	return mongoFrame(mongoOpQuery, 9, body)
}

func cmdDoc(name string, extra func(d *bsonDoc)) []byte {
	d := newBSONDoc().i32(name, 1)
	if extra != nil {
		extra(d)
	}
	return d.str("$db", "admin").bytes()
}

func (d *bsonDoc) binary(k string, v []byte) *bsonDoc {
	d.key(0x05, k)
	d.b = binary.LittleEndian.AppendUint32(d.b, uint32(len(v)))
	d.b = append(d.b, 0)
	d.b = append(d.b, v...)
	return d
}

// readReply reads one reply and returns its opcode, responseTo and the fields of
// the reply document rendered as strings.
func readReply(t *testing.T, conn net.Conn) (opCode int32, responseTo int32, fields map[string]string) {
	t.Helper()
	h, body, err := readMongoMessage(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var doc []byte
	switch h.opCode {
	case mongoOpMsg:
		doc = body[5:]
	case mongoOpReply:
		doc = body[20:]
	default:
		t.Fatalf("unexpected reply opcode %d", h.opCode)
	}
	fields = map[string]string{}
	if err := bsonWalk(doc, func(e bsonElem) bool {
		switch e.typ {
		case 0x02:
			fields[e.key], _ = bsonString(e)
		case 0x10:
			fields[e.key] = fmt.Sprint(int32(binary.LittleEndian.Uint32(e.val)))
		case 0x08:
			fields[e.key] = fmt.Sprint(e.val[0] == 1)
		case 0x01:
			fields[e.key] = fmt.Sprint(math.Float64frombits(binary.LittleEndian.Uint64(e.val)))
		default:
			fields[e.key] = "?"
		}
		return true
	}); err != nil {
		t.Fatalf("reply document: %v", err)
	}
	return h.opCode, h.responseTo, fields
}

// expectClosed asserts that the server closes the connection without a reply.
func expectMongoClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(make([]byte, 64))
	if n != 0 || err == nil {
		t.Fatalf("want a closed connection, read %d bytes, err %v", n, err)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection still open")
	}
}

// --- tests ---

func TestMongoDBHandshakeIsProbe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		request []byte
		wantOp  int32
		want    map[string]string
	}{
		{"hello op_msg", opMsg(cmdDoc("hello", nil), 0), mongoOpMsg, map[string]string{"isWritablePrimary": "true", "maxWireVersion": "17", "ok": "1"}},
		{"isMaster op_msg", opMsg(cmdDoc("isMaster", nil), 0), mongoOpMsg, map[string]string{"ismaster": "true", "ok": "1"}},
		{"isMaster op_query", opQuery("admin.$cmd", newBSONDoc().i32("isMaster", 1).bytes()), mongoOpReply, map[string]string{"ismaster": "true", "ok": "1"}},
		{"ismaster lower case", opQuery("admin.$cmd", newBSONDoc().i32("ismaster", 1).bytes()), mongoOpReply, map[string]string{"ismaster": "true"}},
		{"buildInfo", opMsg(cmdDoc("buildInfo", nil), 0), mongoOpMsg, map[string]string{"version": "6.0.14", "ok": "1"}},
		{"ping", opMsg(cmdDoc("ping", nil), 0), mongoOpMsg, map[string]string{"ok": "1"}},
		{"checksum flag", append(opMsg(cmdDoc("hello", nil), 1), 0, 0, 0, 0), mongoOpMsg, map[string]string{"ok": "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := startMongoDB(t)
			conn := dialTrap(t, h.addr)
			req := tc.request
			if tc.name == "checksum flag" {
				// The frame length must include the four checksum bytes.
				binary.LittleEndian.PutUint32(req, uint32(len(req)))
			}
			if _, err := conn.Write(req); err != nil {
				t.Fatal(err)
			}
			op, to, fields := readReply(t, conn)
			if op != tc.wantOp {
				t.Errorf("reply opcode = %d, want %d", op, tc.wantOp)
			}
			if want := map[bool]int32{true: 9, false: 7}[tc.wantOp == mongoOpReply]; to != want {
				t.Errorf("responseTo = %d, want %d", to, want)
			}
			for k, v := range tc.want {
				if fields[k] != v {
					t.Errorf("%s = %q, want %q (fields %v)", k, fields[k], v, fields)
				}
			}
			conn.Close()
			h.waitClass(t, false)
		})
	}
}

func TestMongoDBUnauthorizedCommandIsAttack(t *testing.T) {
	t.Parallel()
	h := startMongoDB(t)
	conn := dialTrap(t, h.addr)
	if _, err := conn.Write(opMsg(cmdDoc("listDatabases", nil), 0)); err != nil {
		t.Fatal(err)
	}
	_, _, fields := readReply(t, conn)
	if fields["ok"] != "0" || fields["code"] != "13" || fields["codeName"] != "Unauthorized" || !strings.Contains(fields["errmsg"], "listDatabases") {
		t.Errorf("reply = %v", fields)
	}
	// The connection stays usable.
	if _, err := conn.Write(opMsg(cmdDoc("ping", nil), 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, f := readReply(t, conn); f["ok"] != "1" {
		t.Errorf("ping after error = %v", f)
	}
	ev := waitAttack(t, h.sink)
	if ev.Meta["command"] != "listDatabases" || ev.Info.Commands != 1 || ev.Info.SourceIP != "127.0.0.1" {
		t.Errorf("event = %+v", ev)
	}
	if out := h.logs.String(); !strings.Contains(out, `"command":"listDatabases"`) {
		t.Errorf("command not logged:\n%s", out)
	}
}

func TestMongoDBLegacyQueryIsCommand(t *testing.T) {
	t.Parallel()
	h := startMongoDB(t)
	conn := dialTrap(t, h.addr)
	if _, err := conn.Write(opQuery("shop.users", newBSONDoc().str("name", "x").bytes())); err != nil {
		t.Fatal(err)
	}
	op, _, fields := readReply(t, conn)
	if op != mongoOpReply || fields["codeName"] != "Unauthorized" {
		t.Errorf("op %d reply %v", op, fields)
	}
	if ev := waitAttack(t, h.sink); ev.Meta["command"] != "query" {
		t.Errorf("meta = %v", ev.Meta)
	}
}

func TestMongoDBSaslStartIsAuthAttempt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		doc     []byte
		user    string
		secrets []string
	}{
		{"scram", cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "SCRAM-SHA-256").binary("payload", []byte("n,,n=admin,r=clientnonce123"))
		}), "admin", []string{"clientnonce123", "r=client"}},
		{"scram escaped", cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "SCRAM-SHA-1").binary("payload", []byte("n,,n=a=2Cb,r=zz9"))
		}), "a,b", []string{"zz9"}},
		{"plain", cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "PLAIN").binary("payload", []byte("\x00root\x00hunter2pw"))
		}), "root", []string{"hunter2pw"}},
		{"plain with authzid", cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "PLAIN").binary("payload", []byte("admin\x00root\x00hunter2pw"))
		}), "root", []string{"hunter2pw"}},
		{"plain two parts", cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "PLAIN").binary("payload", []byte("root\x00hunter2pw"))
		}), "", []string{"hunter2pw"}},
		{"plain four parts", cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "PLAIN").binary("payload", []byte("a\x00root\x00hunter2pw\x00x"))
		}), "", []string{"hunter2pw"}},
		{"legacy authenticate", cmdDoc("authenticate", func(d *bsonDoc) {
			d.str("user", "mongo").str("nonce", "abc").str("key", "deadbeefproof")
		}), "mongo", []string{"deadbeefproof"}},
		{"no payload", cmdDoc("saslStart", func(d *bsonDoc) { d.str("mechanism", "MONGODB-X509") }), "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := startMongoDB(t)
			conn := dialTrap(t, h.addr)
			if _, err := conn.Write(opMsg(tc.doc, 0)); err != nil {
				t.Fatal(err)
			}
			_, _, fields := readReply(t, conn)
			if fields["codeName"] != "AuthenticationFailed" || fields["code"] != "18" {
				t.Errorf("reply = %v", fields)
			}
			ev := waitAttack(t, h.sink)
			if ev.Info.AuthAttempts != 1 || ev.Meta["username"] != tc.user {
				t.Errorf("auth = %d meta = %v, want user %q", ev.Info.AuthAttempts, ev.Meta, tc.user)
			}
			if len(ev.Meta) > 2 {
				t.Errorf("meta carries more than username and mechanism: %v", ev.Meta)
			}
			out := h.logs.String()
			for _, s := range tc.secrets {
				if strings.Contains(out, s) {
					t.Errorf("log leaks %q:\n%s", s, out)
				}
				for k, v := range ev.Meta {
					if strings.Contains(v, s) {
						t.Errorf("meta %s=%q leaks %q", k, v, s)
					}
				}
			}
			if !strings.Contains(out, `"action":"auth_attempt"`) {
				t.Errorf("auth attempt not logged:\n%s", out)
			}
			if strings.Contains(out, `"password"`) {
				t.Errorf("log has a password attribute:\n%s", out)
			}
		})
	}
}

func TestMongoDBLongValuesAreBounded(t *testing.T) {
	t.Parallel()
	h := startMongoDB(t)
	conn := dialTrap(t, h.addr)
	longName := strings.Repeat("c", 3000) + "\n"
	doc := newBSONDoc().i32(longName, 1).str("$db", strings.Repeat("d", 3000)).bytes()
	if _, err := conn.Write(opMsg(doc, 0)); err != nil {
		t.Fatal(err)
	}
	_, _, fields := readReply(t, conn)
	if len(fields["errmsg"]) > 128 {
		t.Errorf("errmsg is %d bytes", len(fields["errmsg"]))
	}
	ev := waitAttack(t, h.sink)
	if len(ev.Meta["command"]) > maxCommandNameBytes || !utf8.ValidString(ev.Meta["command"]) {
		t.Errorf("command meta is %d bytes", len(ev.Meta["command"]))
	}
}

func TestMongoDBMalformedAndOversizedClose(t *testing.T) {
	t.Parallel()
	hdr := func(length uint32) []byte {
		b := binary.LittleEndian.AppendUint32(nil, length)
		return append(b, make([]byte, 12)...)
	}
	badDoc := opMsg([]byte{0xFF, 0xFF, 0xFF, 0x7F, 0x10, 'a', 0, 1, 0, 0, 0, 0}, 0)
	shortDoc := opMsg([]byte{1, 0, 0, 0, 0}, 0)
	emptyDoc := opMsg([]byte{5, 0, 0, 0, 0}, 0)
	badFlags := func() []byte {
		b := opMsg(cmdDoc("hello", nil), 0)
		b[16] = 0x04
		return b
	}()
	badSection := func() []byte {
		b := opMsg(cmdDoc("hello", nil), 0)
		b[20] = 9
		return b
	}()
	cases := []struct {
		name string
		in   []byte
	}{
		{"length 48MB", hdr(48000000)},
		{"length max uint32", hdr(0xFFFFFFFF)},
		{"length just over limit", hdr(maxMongoMessage + 1)},
		{"length below header", hdr(8)},
		{"element length beyond document", badDoc},
		{"document shorter than minimum", shortDoc},
		{"empty command document", emptyDoc},
		{"unknown required flag bit", badFlags},
		{"unknown section kind", badSection},
		{"truncated body", mongoFrame(mongoOpMsg, 1, []byte{0, 0})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := startMongoDB(t)
			conn := dialTrap(t, h.addr)
			if _, err := conn.Write(tc.in); err != nil {
				t.Fatal(err)
			}
			expectMongoClosed(t, conn)
			h.waitClass(t, false)
		})
	}
}

func TestMongoDBUnsupportedOpcodeCountsAsPayload(t *testing.T) {
	t.Parallel()
	h := startMongoDB(t)
	conn := dialTrap(t, h.addr)
	if _, err := conn.Write(mongoFrame(2012, 1, bytes.Repeat([]byte{1}, 40))); err != nil {
		t.Fatal(err)
	}
	expectMongoClosed(t, conn)
	if ev := waitAttack(t, h.sink); ev.Info.PayloadBytes != 40 {
		t.Errorf("payload bytes = %d, want 40", ev.Info.PayloadBytes)
	}
}

func TestMongoDBMoreToComeGetsNoReply(t *testing.T) {
	t.Parallel()
	h := startMongoDB(t)
	conn := dialTrap(t, h.addr)
	var req []byte
	req = append(req, opMsg(cmdDoc("ping", nil), mongoMsgMoreToCome)...)
	req = append(req, opMsg(cmdDoc("buildInfo", nil), 0)...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	// The first reply received belongs to buildInfo.
	if _, _, f := readReply(t, conn); f["version"] == "" {
		t.Errorf("first reply = %v, want buildInfo", f)
	}
}

func TestMongoDBStopClosesConnections(t *testing.T) {
	t.Parallel()
	h := startMongoDB(t)
	conn := dialTrap(t, h.addr)
	if _, err := conn.Write(opMsg(cmdDoc("ping", nil), 0)); err != nil {
		t.Fatal(err)
	}
	readReply(t, conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.trap.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := h.trap.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	expectMongoClosed(t, conn)
}

func TestMongoDBTimeoutOutcome(t *testing.T) {
	t.Parallel()
	// A header that promises a body that never arrives ends at the session
	// timeout, not with a hang.
	cfg := &config.Config{
		Addrs:          map[string]string{"mongodb": "127.0.0.1:0"},
		SessionTimeout: 300 * time.Millisecond,
		MaxSessions:    10,
		MaxPerIP:       10,
	}
	tr := NewMongoDB(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, NewLimiter(10, 10), alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := serveTrap(t, ctx, tr)
	conn := dialTrap(t, addr)
	if _, err := conn.Write(binary.LittleEndian.AppendUint32(nil, 1000)); err != nil {
		t.Fatal(err)
	}
	expectMongoClosed(t, conn)
}

// --- reader and BSON unit tests ---

func TestReadMongoMessageBounds(t *testing.T) {
	t.Parallel()
	good := mongoFrame(mongoOpMsg, 1, []byte{1, 2, 3, 4})
	h, body, err := readMongoMessage(bytes.NewReader(good))
	if err != nil || h.opCode != mongoOpMsg || len(body) != 4 {
		t.Fatalf("good frame: %+v %v %v", h, body, err)
	}
	if _, _, err := readMongoMessage(bytes.NewReader(good[:len(good)-1])); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated body error = %v", err)
	}
	if _, _, err := readMongoMessage(bytes.NewReader(nil)); err != io.EOF {
		t.Errorf("empty input error = %v", err)
	}
	// A huge declared length must fail before anything is read or allocated.
	huge := binary.LittleEndian.AppendUint32(nil, 0x7FFFFFFF)
	huge = append(huge, make([]byte, 12)...)
	r := &countingReader{r: bytes.NewReader(append(huge, make([]byte, 100000)...))}
	if _, _, err := readMongoMessage(r); err == nil {
		t.Fatal("huge length accepted")
	}
	if r.n > mongoHeaderLen {
		t.Errorf("read %d bytes after a bad header", r.n)
	}
	// A frame at exactly the limit is accepted.
	max := mongoFrame(mongoOpMsg, 1, make([]byte, maxMongoMessage-mongoHeaderLen))
	if _, body, err := readMongoMessage(bytes.NewReader(max)); err != nil || len(body) != maxMongoMessage-mongoHeaderLen {
		t.Errorf("frame at the limit: %d bytes, err %v", len(body), err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestBSONWalk(t *testing.T) {
	t.Parallel()
	nested := newBSONDoc().i32("a", 1)
	nested.key(0x03, "sub")
	nested.b = append(nested.b, newBSONDoc().str("x", "y").bytes()...)
	nested.ints("arr", 1, 2, 3)
	nested.double("d", 1.5).boolean("b", true).datetime("t", time.Unix(1, 0)).binary("bin", []byte("zz")).str("s", "end")
	var keys []string
	if err := bsonWalk(nested.bytes(), func(e bsonElem) bool { keys = append(keys, e.key); return true }); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys, ","); got != "a,sub,arr,d,b,t,bin,s" {
		t.Errorf("keys = %s", got)
	}

	// Stops when fn says so.
	n := 0
	_ = bsonWalk(nested.bytes(), func(bsonElem) bool { n++; return false })
	if n != 1 {
		t.Errorf("visited %d elements, want 1", n)
	}

	// Only the first maxBSONElements elements are walked.
	many := newBSONDoc()
	for i := 0; i < maxBSONElements*3; i++ {
		many.i32(fmt.Sprintf("k%d", i), 1)
	}
	n = 0
	_ = bsonWalk(many.bytes(), func(bsonElem) bool { n++; return true })
	if n != maxBSONElements {
		t.Errorf("walked %d elements, want %d", n, maxBSONElements)
	}

	// Malformed documents.
	bad := map[string][]byte{
		"empty":             nil,
		"short":             {1, 2, 3},
		"length beyond":     {0xFF, 0xFF, 0xFF, 0xFF, 0},
		"length below five": {4, 0, 0, 0, 0},
		"no terminator":     {5, 0, 0, 0, 1},
		"unterminated key":  {8, 0, 0, 0, 0x10, 'a', 'b', 0},
		"string too long":   {13, 0, 0, 0, 0x02, 'a', 0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0},
		"string zero len":   {12, 0, 0, 0, 0x02, 'a', 0, 0, 0, 0, 0, 0},
		"unknown type":      {8, 0, 0, 0, 0x55, 'a', 0, 0},
		"int32 truncated":   {9, 0, 0, 0, 0x10, 'a', 0, 1, 0},
		"binary huge":       {14, 0, 0, 0, 0x05, 'a', 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0},
		"subdoc huge":       {12, 0, 0, 0, 0x03, 'a', 0, 0xFF, 0xFF, 0xFF, 0x7F, 0},
	}
	for name, doc := range bad {
		if err := bsonWalk(doc, func(bsonElem) bool { return true }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMongoSASLUser(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"n,,n=admin,r=abc":     "admin",
		"y,,n=bob,r=abc":       "bob",
		"n,a=authz,n=al,r=x":   "al",
		"n,,n=a=2Cb=3Dc,r=x":   "a,b=c",
		"\x00root\x00secret":   "root",
		"\x00root":             "",
		"root\x00hunter2":      "",
		"a\x00b\x00c":          "b",
		"a\x00b\x00c\x00d":     "",
		"\x00\x00pw":           "",
		"\x00\x00\x00":         "",
		"\x00":                 "",
		"garbage without user": "",
		"":                     "",
	}
	for in, want := range cases {
		if got := mongoSASLUser([]byte(in)); got != want {
			t.Errorf("mongoSASLUser(%q) = %q, want %q", in, got, want)
		}
	}
	long := append([]byte("n,,n="), bytes.Repeat([]byte("u"), 5000)...)
	if got := mongoSASLUser(long); len(got) > maxMongoSASLPayload {
		t.Errorf("user of %d bytes is not bounded", len(got))
	}
	// A very long PLAIN payload: the user is bounded and the password never returned.
	longPlain := append([]byte("\x00"+strings.Repeat("u", 3000)+"\x00"), bytes.Repeat([]byte("p"), 5000)...)
	if got := mongoSASLUser(longPlain); len(got) > maxMongoSASLPayload || strings.Contains(got, "p") {
		t.Errorf("long PLAIN user = %d bytes", len(got))
	}
	// Two NUL separated parts: the second one is a password, never a user name.
	if got := mongoSASLUser([]byte(strings.Repeat("r", 3000) + "\x00" + strings.Repeat("p", 3000))); got != "" {
		t.Errorf("long two part payload returned %d bytes", len(got))
	}
}

func TestMongoDBAuthUserKeepsUTF8(t *testing.T) {
	t.Parallel()
	h := startMongoDB(t)
	conn := dialTrap(t, h.addr)
	user := strings.Repeat("€", 43) // 129 bytes, one over maxMongoAuthField
	doc := cmdDoc("saslStart", func(d *bsonDoc) {
		d.str("mechanism", "PLAIN").binary("payload", []byte("\x00"+user+"\x00pw"))
	})
	if _, err := conn.Write(opMsg(doc, 0)); err != nil {
		t.Fatal(err)
	}
	readReply(t, conn)
	ev := waitAttack(t, h.sink)
	got := ev.Meta["username"]
	if !utf8.ValidString(got) || len(got) > maxMongoAuthField || got == "" {
		t.Errorf("username meta = %q (%d bytes)", got, len(got))
	}
}

// Not parallel: it switches the package-level password log mode.
// No secret of a SASL or legacy authentication reaches CrowdSec, whatever the
// payload shape.
func TestMongoDBNoPasswordReachesCrowdSec(t *testing.T) {
	SetPasswordLogMode("on")
	defer SetPasswordLogMode("off")
	lapi := &fakeLAPI{}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry(), "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink, err := alert.NewCrowdSec(ctx, alert.CrowdSecConfig{
		URL: srv.URL, MachineID: "ran", Password: "lapi-secret", BatchInterval: 50 * time.Millisecond, BatchSize: 1,
	}, logger, m)
	if err != nil {
		t.Fatal(err)
	}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, sink, logger)
	defer sensor.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"mongodb": "127.0.0.1:0"},
		PerProto:       make(map[string]config.ProtoConfig),
		ProxyProtocol:  true,
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
	tr := NewMongoDB(cfg, logger, m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	addr := serveTrap(t, ctx, tr)

	docs := [][]byte{
		cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "SCRAM-SHA-256").binary("payload", []byte("n,,n=admin,r=nonce-s3cret"))
		}),
		cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "PLAIN").binary("payload", []byte("\x00root\x00pw-three-part"))
		}),
		cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "PLAIN").binary("payload", []byte("root\x00pw-two-part"))
		}),
		cmdDoc("saslStart", func(d *bsonDoc) {
			d.str("mechanism", "PLAIN").binary("payload", []byte("a\x00root\x00pw-four\x00part"))
		}),
		cmdDoc("authenticate", func(d *bsonDoc) {
			d.str("user", "mongo").str("nonce", "abc").str("key", "proof-s3cret")
		}),
	}
	for i, doc := range docs {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 40000 27017\r\n", fmt.Sprintf("8.8.8.%d", i+1))
		if _, err := conn.Write(opMsg(doc, 0)); err != nil {
			t.Fatal(err)
		}
		readReply(t, conn)
		conn.Close()
	}
	waitFor(t, func() bool { return lapi.acceptedCount() >= len(docs) })
	time.Sleep(300 * time.Millisecond)

	lapi.mu.Lock()
	defer lapi.mu.Unlock()
	raw, err := json.Marshal(lapi.accepted)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"nonce-s3cret", "pw-three-part", "pw-two-part", "pw-four", "proof-s3cret", `"key":"password"`} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q reached CrowdSec: %s", secret, raw)
		}
	}
	for _, want := range []string{`"admin"`, `"root"`, `"mongo"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("expected user %s in the pushed alerts: %s", want, raw)
		}
	}
}

func TestMongoReplyFraming(t *testing.T) {
	t.Parallel()
	doc := mongoOKDoc()
	msg := mongoReply(mongoRequest{opCode: mongoOpMsg}, mongoHeader{requestID: 5}, 2, doc)
	h, body, err := readMongoMessage(bytes.NewReader(msg))
	if err != nil || h.opCode != mongoOpMsg || h.responseTo != 5 || h.requestID != 2 || !bytes.HasSuffix(body, doc) {
		t.Errorf("OP_MSG reply: %+v err %v", h, err)
	}
	rep := mongoReply(mongoRequest{opCode: mongoOpQuery}, mongoHeader{requestID: 6}, 3, doc)
	h, body, err = readMongoMessage(bytes.NewReader(rep))
	if err != nil || h.opCode != mongoOpReply || h.responseTo != 6 || len(body) != 20+len(doc) {
		t.Errorf("OP_REPLY: %+v len %d err %v", h, len(body), err)
	}
}

func TestFitsIntMongo32Bit(t *testing.T) {
	t.Parallel()
	if _, ok := fitsInt(0xFFFFFFFF, math.MaxInt32); ok {
		t.Error("a length above a 32-bit int must not fit")
	}
}
