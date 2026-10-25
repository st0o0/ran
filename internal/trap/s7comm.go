package trap

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	// s7MaxTPKT bounds the declared TPKT length. Real S7 PDUs stay below 960
	// bytes; a larger declared length ends the session before anything is read.
	s7MaxTPKT = 1024
	// s7MaxPackets bounds the TPKT packets served per session.
	s7MaxPackets = 64

	cotpCR = 0xE0
	cotpCC = 0xD0
	cotpDR = 0x80
	cotpDT = 0xF0

	s7ProtocolID = 0x32
	s7Job        = 0x01
	s7AckData    = 0x03
	s7Userdata   = 0x07

	s7FuncSetup    = 0xF0
	s7FuncReadVar  = 0x04
	s7FuncWriteVar = 0x05

	s7KindSetup    = "setup"
	s7KindIdentify = "identify"
	s7KindWrite    = "write"
	s7KindControl  = "control"
	s7KindUnknown  = "unknown"

	// S7 error class and code of a refused request ("function not supported").
	s7ErrClass = 0x81
	s7ErrCode  = 0x04
)

var errS7Malformed = errors.New("s7comm: not a TPKT packet")

// S7Trap is a stub of an S7 PLC (ISO on TCP, port 102). It answers the COTP
// connection request, the setup communication request and SZL reads with a
// fixed identity. Writes, block transfers, PLC control and unknown functions are
// refused with an S7 error and recorded as payload.
type S7Trap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewS7Comm(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *S7Trap {
	t := &S7Trap{cfg: cfg, logger: logger, metrics: m}
	t.tcpServer = newTCPServer("s7comm", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

// readTPKT reads one TPKT (RFC 1006) packet. The declared length is checked
// against s7MaxTPKT before anything is allocated, so the payload is never larger
// than the bytes read. hdr is returned for diagnostics even on error. A length
// above the cap is bufio.ErrTooLong; a bad version or a length below the header
// is errS7Malformed.
func readTPKT(r io.Reader) (hdr [4]byte, payload []byte, err error) {
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return hdr, nil, err
	}
	if hdr[0] != 3 || hdr[1] != 0 {
		return hdr, nil, errS7Malformed
	}
	total, ok := fitsInt(uint32(binary.BigEndian.Uint16(hdr[2:4])), s7MaxTPKT)
	if !ok {
		return hdr, nil, bufio.ErrTooLong
	}
	if total < 4+2 {
		return hdr, nil, errS7Malformed
	}
	payload = make([]byte, total-4)
	if _, err = io.ReadFull(r, payload); err != nil {
		return hdr, nil, err
	}
	return hdr, payload, nil
}

// s7Request is what the trap decodes from one TPKT payload.
type s7Request struct {
	// cotp is the COTP PDU type (high nibble kept for CR and CC).
	cotp byte
	// srcRef is the source reference of a connection request.
	srcRef [2]byte
	// kind is one of the s7Kind constants; empty for a COTP packet without S7 data.
	kind string
	// function is the S7 job function code, or -1.
	function int
	pduRef   uint16
	// szlID is the SZL id of an SZL read, or -1.
	szlID int
	// userGroup, userSub and userSeq describe a userdata request.
	userGroup, userSub, userSeq byte
}

// parseS7 decodes a TPKT payload (COTP header and S7 PDU). It never allocates
// from a decoded length and ignores everything it does not understand.
func parseS7(p []byte) s7Request {
	req := s7Request{function: -1, szlID: -1}
	if len(p) < 2 {
		return req
	}
	li := int(p[0])
	req.cotp = p[1]
	switch req.cotp {
	case cotpCR:
		if len(p) >= 6 {
			copy(req.srcRef[:], p[4:6])
		}
		return req
	case cotpDT:
	default:
		return req
	}
	if 1+li > len(p) {
		req.kind = s7KindUnknown
		return req
	}
	s := p[1+li:]
	if len(s) < 10 || s[0] != s7ProtocolID {
		req.kind = s7KindUnknown
		return req
	}
	rosctr := s[1]
	req.pduRef = binary.BigEndian.Uint16(s[4:6])
	plen, ok := fitsInt(uint32(binary.BigEndian.Uint16(s[6:8])), uint64(len(s)-10))
	if !ok || plen == 0 {
		req.kind = s7KindUnknown
		return req
	}
	param := s[10 : 10+plen]
	switch rosctr {
	case s7Job:
		req.function = int(param[0])
		switch param[0] {
		case s7FuncSetup:
			req.kind = s7KindSetup
		case s7FuncReadVar:
			req.kind = s7KindIdentify
		case s7FuncWriteVar:
			req.kind = s7KindWrite
		case 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29:
			// Download, upload, PLC control and PLC stop.
			req.kind = s7KindControl
		default:
			req.kind = s7KindUnknown
		}
	case s7Userdata:
		req.kind = s7KindUnknown
		if len(param) >= 8 && param[0] == 0 && param[1] == 1 && param[2] == 0x12 {
			req.userGroup = param[5] & 0x0F
			req.userSub = param[6]
			req.userSeq = param[7]
			switch {
			case req.userGroup == 4 && req.userSub == 1:
				// SZL read.
				req.kind = s7KindIdentify
				d := s[10+plen:]
				if len(d) >= 8 && d[0] == 0xFF {
					req.szlID = int(binary.BigEndian.Uint16(d[4:6]))
				}
			case req.userGroup == 3:
				// Block functions (list blocks): read only, answered with an error.
				req.kind = s7KindIdentify
			}
		}
	default:
		req.kind = s7KindUnknown
	}
	return req
}

func tpkt(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0], out[1] = 3, 0
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	copy(out[4:], payload)
	return out
}

// s7ConnectConfirm builds the COTP connection confirm with fixed TSAPs.
func s7ConnectConfirm(srcRef [2]byte) []byte {
	return tpkt([]byte{
		0x11, cotpCC,
		srcRef[0], srcRef[1], // destination reference: the client's source reference
		0x00, 0x01, // source reference
		0x00,
		0xC0, 0x01, 0x0A, // TPDU size 1024
		0xC1, 0x02, 0x01, 0x00, // calling TSAP
		0xC2, 0x02, 0x01, 0x02, // called TSAP
	})
}

func s7Wrap(pdu []byte) []byte {
	return tpkt(append([]byte{0x02, cotpDT, 0x80}, pdu...))
}

// s7AckError builds an Ack_Data PDU that carries an S7 error.
func s7AckError(pduRef uint16) []byte {
	pdu := []byte{s7ProtocolID, s7AckData, 0, 0, 0, 0, 0, 0, 0, 0, s7ErrClass, s7ErrCode}
	binary.BigEndian.PutUint16(pdu[4:6], pduRef)
	return s7Wrap(pdu)
}

// s7SetupAck answers the setup communication request with one job in each
// direction and a PDU size of 480.
func s7SetupAck(pduRef uint16) []byte {
	pdu := []byte{
		s7ProtocolID, s7AckData, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,
		s7FuncSetup, 0, 0, 1, 0, 1, 0x01, 0xE0,
	}
	binary.BigEndian.PutUint16(pdu[4:6], pduRef)
	return s7Wrap(pdu)
}

// Fixed identity. Everything here is invented: it does not name a real device or
// serial number.
const (
	s7ModuleMLFB   = "6ES7 315-2EH14-0AB0 "
	s7SystemName   = "SIMATIC 300(1)"
	s7ModuleName   = "CPU 315-2 PN/DP"
	s7Copyright    = "Original Siemens Equipment"
	s7SerialNumber = "S C-X0RAN0000001"
	s7ModuleType   = "CPU 315-2 PN/DP"
)

func padTo(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}

// s7SZLRecords returns the fixed records of an SZL id and the record size.
func s7SZLRecords(id int) (records []byte, size int, ok bool) {
	rec := func(idx uint16, body []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, idx), body...)
	}
	switch id {
	case 0x0011:
		// Module identification: index, MlfB (20), BGTyp, Ausbg1, Ausbg2.
		mk := func(idx uint16, version uint16) []byte {
			body := append(padTo(s7ModuleMLFB, 20), 0, 0, 0, 0)
			body = binary.BigEndian.AppendUint16(body, version)
			return rec(idx, body)
		}
		out := append(mk(0x0001, 0x0001), mk(0x0006, 0x0001)...)
		out = append(out, mk(0x0007, 0x2001)...)
		return out, 28, true
	case 0x001C:
		// Component identification: index and a 32 byte string.
		var out []byte
		for _, e := range []struct {
			idx uint16
			s   string
		}{
			{1, s7SystemName}, {2, s7ModuleName}, {4, s7Copyright}, {5, s7SerialNumber}, {7, s7ModuleType},
		} {
			out = append(out, rec(e.idx, padTo(e.s, 32))...)
		}
		return out, 34, true
	}
	return nil, 0, false
}

// s7SZLResponse answers an SZL read. An SZL id the trap has no data for gets the
// "object does not exist" return code.
func s7SZLResponse(req s7Request) []byte {
	records, size, ok := s7SZLRecords(req.szlID)
	var data []byte
	if ok {
		data = []byte{0xFF, 0x09, 0, 0}
		data = binary.BigEndian.AppendUint16(data, uint16(req.szlID))
		data = binary.BigEndian.AppendUint16(data, 0) // index
		data = binary.BigEndian.AppendUint16(data, uint16(size))
		data = binary.BigEndian.AppendUint16(data, uint16(len(records)/size))
		data = append(data, records...)
		binary.BigEndian.PutUint16(data[2:4], uint16(len(data)-4))
	} else {
		data = []byte{0x0A, 0x00, 0x00, 0x00}
	}
	return s7UserdataResponse(req, data, 0)
}

func s7UserdataResponse(req s7Request, data []byte, errCode uint16) []byte {
	param := []byte{0x00, 0x01, 0x12, 0x08, 0x12, 0x80 | req.userGroup, req.userSub, req.userSeq, 0, 0}
	param = binary.BigEndian.AppendUint16(param, errCode)
	pdu := []byte{s7ProtocolID, s7Userdata, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(pdu[4:6], req.pduRef)
	binary.BigEndian.PutUint16(pdu[6:8], uint16(len(param)))
	binary.BigEndian.PutUint16(pdu[8:10], uint16(len(data)))
	pdu = append(pdu, param...)
	pdu = append(pdu, data...)
	return s7Wrap(pdu)
}

// s7Response builds the answer to a decoded request. A nil result means there is
// nothing to send.
func s7Response(req s7Request) []byte {
	switch req.cotp {
	case cotpCR:
		return s7ConnectConfirm(req.srcRef)
	case cotpDT:
	default:
		return nil
	}
	switch {
	case req.kind == s7KindSetup:
		return s7SetupAck(req.pduRef)
	case req.kind == s7KindIdentify && req.szlID >= 0:
		return s7SZLResponse(req)
	case req.kind == s7KindIdentify && req.function < 0:
		return s7UserdataResponse(req, []byte{0x0A, 0x00, 0x00, 0x00}, 0x8104)
	default:
		return s7AckError(req.pduRef)
	}
}

func (t *S7Trap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	for range s7MaxPackets {
		hdr, payload, err := readTPKT(conn)
		switch {
		case errors.Is(err, errS7Malformed):
			// Not S7: keep the four bytes that were read as the payload.
			raw := hex.EncodeToString(hdr[:])
			sess.LogPayloadSize("s7comm_unknown", len(hdr), slog.String("raw", raw))
			sess.Alert(ctx, map[string]string{"kind": s7KindUnknown})
			return
		case err != nil:
			// A declared length above the cap is bufio.ErrTooLong (outcome too_long).
			setOutcome(sess, err)
			return
		}

		req := parseS7(payload)
		switch req.cotp {
		case cotpDR:
			return
		case cotpCR:
			sess.Log("s7comm_request", slog.String("kind", "connect"))
		case cotpDT:
			t.record(ctx, sess, req, len(payload))
		default:
			sess.LogPayloadSize("s7comm_cotp", len(payload), slog.Int("cotp_type", int(req.cotp)))
			sess.Alert(ctx, map[string]string{"kind": s7KindUnknown})
		}

		if resp := s7Response(req); resp != nil {
			if _, err := conn.Write(resp); err != nil {
				setOutcome(sess, err)
				return
			}
		}
	}
}

// record logs one data packet. Setup and identification are fingerprinting and
// stay a probe; everything else is payload with an alert.
func (t *S7Trap) record(ctx context.Context, sess *Session, req s7Request, size int) {
	attrs := []slog.Attr{slog.String("kind", req.kind)}
	if req.function >= 0 {
		attrs = append(attrs, slog.Int("function_code", req.function))
	}
	if req.kind == s7KindSetup || req.kind == s7KindIdentify {
		sess.Log("s7comm_request", attrs...)
		return
	}
	sess.LogPayloadSize("s7comm_request", size, attrs...)
	meta := map[string]string{"kind": req.kind}
	if req.function >= 0 {
		meta["function_code"] = strconv.Itoa(req.function)
	}
	sess.Alert(ctx, meta)
}
