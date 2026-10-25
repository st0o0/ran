package trap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// sensorMetaKeys are the keys the sensor adds to every alert.
var sensorMetaKeys = map[string]bool{
	"class": true, "protocol": true, "dest_port": true,
	"auth_attempts": true, "commands": true, "payload_bytes": true,
}

// trapMetaKeys returns the sorted trap specific meta keys of an event.
func trapMetaKeys(ev alert.Event) []string {
	var keys []string
	for k := range ev.Meta {
		if !sensorMetaKeys[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func assertMetaKeys(t *testing.T, ev alert.Event, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := trapMetaKeys(ev); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("meta keys = %v, want %v (meta %v)", got, want, ev.Meta)
	}
	for k, v := range ev.Meta {
		if len(v) > 256 {
			t.Errorf("meta %s is %d bytes", k, len(v))
		}
		switch strings.ToLower(k) {
		case "password", "pass", "passwd", "secret", "token", "authorization":
			t.Errorf("secret key %s in meta", k)
		}
	}
}

// icsTrap is a started trap with a handle for Stop.
type icsTrap struct {
	*depthTrap
	trap Trap
}

func startICS(t *testing.T, name string, build trapBuilder) *icsTrap {
	t.Helper()
	var tr Trap
	d := startDepthTrap(t, name, nil, func(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
		tr = build(c, l, m, lim, r)
		return tr
	})
	return &icsTrap{depthTrap: d, trap: tr}
}

func buildS7(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewS7Comm(c, l, m, lim, r)
}

func buildENIP(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewENIP(c, l, m, lim, r)
}

func buildPJL(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewPJL(c, l, m, lim, r)
}

func buildIPP(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewIPP(c, l, m, lim, r)
}

// assertStopClosesConn checks that Stop(ctx) closes a live connection promptly.
func assertStopClosesConn(t *testing.T, it *icsTrap, conn net.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := it.trap.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := it.trap.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Errorf("connection not closed cleanly after Stop: %v", err)
	}
}

// ---- S7comm ----

func s7TPKT(payload []byte) []byte { return tpkt(payload) }

func s7CR() []byte {
	return s7TPKT([]byte{0x11, cotpCR, 0, 0, 0x12, 0x34, 0, 0xC0, 1, 0x0A, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2})
}

func s7JobReq(pduRef uint16, param []byte, data []byte) []byte {
	pdu := []byte{s7ProtocolID, s7Job, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(pdu[4:6], pduRef)
	binary.BigEndian.PutUint16(pdu[6:8], uint16(len(param)))
	binary.BigEndian.PutUint16(pdu[8:10], uint16(len(data)))
	pdu = append(pdu, param...)
	pdu = append(pdu, data...)
	return s7TPKT(append([]byte{0x02, cotpDT, 0x80}, pdu...))
}

func s7SetupReq() []byte {
	return s7JobReq(1, []byte{s7FuncSetup, 0, 0, 1, 0, 1, 0x03, 0xC0}, nil)
}

func s7SZLReq(id uint16) []byte {
	pdu := []byte{s7ProtocolID, s7Userdata, 0, 0, 0, 7, 0, 8, 0, 8}
	pdu = append(pdu, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00)
	pdu = append(pdu, 0xFF, 0x09, 0x00, 0x04)
	pdu = binary.BigEndian.AppendUint16(pdu, id)
	pdu = append(pdu, 0, 0)
	return s7TPKT(append([]byte{0x02, cotpDT, 0x80}, pdu...))
}

func readS7(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_, payload, err := readTPKT(conn)
	if err != nil {
		t.Fatalf("read TPKT: %v", err)
	}
	return payload
}

func TestS7ProbePathStaysProbe(t *testing.T) {
	t.Parallel()
	it := startICS(t, "s7comm", buildS7)
	conn := dialTrap(t, it.addr)

	_, _ = conn.Write(s7CR())
	cc := readS7(t, conn)
	if cc[1] != cotpCC || cc[2] != 0x12 || cc[3] != 0x34 {
		t.Errorf("connection confirm = %x, want dst ref 1234", cc)
	}

	_, _ = conn.Write(s7SetupReq())
	ack := readS7(t, conn)
	// COTP DT (3 bytes), S7 ack data header (12 bytes incl. error), setup params.
	s := ack[3:]
	if s[0] != s7ProtocolID || s[1] != s7AckData || s[4] != 0 || s[5] != 1 {
		t.Errorf("setup ack header = %x", s)
	}
	if !bytes.Contains(s, []byte{s7FuncSetup, 0, 0, 1, 0, 1, 0x01, 0xE0}) {
		t.Errorf("setup ack params missing: %x", s)
	}

	for id, want := range map[uint16]string{0x001C: s7SerialNumber, 0x0011: "6ES7 315-2EH14-0AB0"} {
		_, _ = conn.Write(s7SZLReq(id))
		resp := readS7(t, conn)
		if !bytes.Contains(resp, []byte(want)) {
			t.Errorf("SZL 0x%04x response lacks %q: %q", id, want, resp)
		}
	}
	// An SZL id without data gets the object-not-found return code.
	_, _ = conn.Write(s7SZLReq(0x7777))
	if resp := readS7(t, conn); !bytes.HasSuffix(resp, []byte{0x0A, 0, 0, 0}) {
		t.Errorf("unknown SZL response = %x", resp)
	}
	// A read variable request is fingerprinting and gets an S7 error.
	_, _ = conn.Write(s7JobReq(9, []byte{s7FuncReadVar, 1, 0x12, 0x0A, 0x10, 0x02, 0, 1, 0, 0, 0x84, 0, 0, 0}, nil))
	if resp := readS7(t, conn); resp[3+1] != s7AckData || !bytes.HasSuffix(resp, []byte{s7ErrClass, s7ErrCode}) {
		t.Errorf("read var response = %x", resp)
	}
	conn.Close()

	if got := it.sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("class = %s, want probe", got)
	}
	if hasClass(it.sink.snapshot(), alert.ClassAttack) {
		t.Error("probe path produced an attack")
	}
	if strings.Contains(it.logs.String(), `"action":"payload"`) {
		t.Error("probe path logged a payload")
	}
}

func TestS7AttackKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		fn       byte
		kind     string
		function string
	}{
		{"write var", s7FuncWriteVar, s7KindWrite, "5"},
		{"request download", 0x1A, s7KindControl, "26"},
		{"download block", 0x1B, s7KindControl, "27"},
		{"start upload", 0x1D, s7KindControl, "29"},
		{"plc control", 0x28, s7KindControl, "40"},
		{"plc stop", 0x29, s7KindControl, "41"},
		{"unknown function", 0x77, s7KindUnknown, "119"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			it := startICS(t, "s7comm", buildS7)
			conn := dialTrap(t, it.addr)
			_, _ = conn.Write(s7CR())
			readS7(t, conn)
			_, _ = conn.Write(s7JobReq(3, []byte{tc.fn, 0, 0}, bytes.Repeat([]byte{0xAA}, 40)))
			resp := readS7(t, conn)
			if resp[3+1] != s7AckData || !bytes.HasSuffix(resp, []byte{s7ErrClass, s7ErrCode}) {
				t.Errorf("response = %x, want an S7 error", resp)
			}
			ev := waitAttack(t, it.sink)
			assertMetaKeys(t, ev, "kind", "function_code")
			if ev.Meta["kind"] != tc.kind || ev.Meta["function_code"] != tc.function {
				t.Errorf("meta = %v, want kind %s function %s", ev.Meta, tc.kind, tc.function)
			}
			if ev.Info.SourceIP != "127.0.0.1" || ev.Info.PayloadBytes == 0 {
				t.Errorf("info = %+v", ev.Info)
			}
			if !strings.Contains(it.logs.String(), `"action":"payload"`) {
				t.Error("no payload log line")
			}
		})
	}
}

func TestS7MalformedAndOversized(t *testing.T) {
	t.Parallel()
	t.Run("oversized TPKT closes without reading it", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "s7comm", buildS7)
		conn := dialTrap(t, it.addr)
		_, _ = conn.Write([]byte{3, 0, 0xFF, 0xFF})
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Errorf("want a clean close, got %v", err)
		}
		it.waitOutcomeLabel(t, "s7comm", outcomeTooLong)
		if hasClass(it.sink.snapshot(), alert.ClassAttack) {
			t.Error("oversized TPKT must not be an attack")
		}
	})
	t.Run("at the limit is read", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "s7comm", buildS7)
		conn := dialTrap(t, it.addr)
		// A junk COTP payload of exactly the maximum size.
		p := make([]byte, s7MaxTPKT-4)
		p[0], p[1] = 0x02, 0xF0
		_, _ = conn.Write(tpkt(p))
		ack := readS7(t, conn)
		if ack[3+1] != s7AckData {
			t.Errorf("response = %x", ack)
		}
		waitAttack(t, it.sink)
	})
	t.Run("not TPKT", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "s7comm", buildS7)
		conn := dialTrap(t, it.addr)
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		ev := waitAttack(t, it.sink)
		assertMetaKeys(t, ev, "kind")
		if ev.Meta["kind"] != s7KindUnknown {
			t.Errorf("kind = %s", ev.Meta["kind"])
		}
		if !strings.Contains(it.logs.String(), `"raw":"47455420"`) {
			t.Errorf("raw header missing from log: %s", it.logs.String())
		}
	})
	t.Run("truncated packet", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "s7comm", buildS7)
		conn := dialTrap(t, it.addr)
		full := s7SetupReq()
		_, _ = conn.Write(full[:len(full)-5])
		conn.Close()
		it.waitOutcomeLabel(t, "s7comm", outcomeError)
		if hasClass(it.sink.snapshot(), alert.ClassAttack) {
			t.Error("truncated packet must not be an attack")
		}
	})
	t.Run("short TPKT length", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "s7comm", buildS7)
		conn := dialTrap(t, it.addr)
		_, _ = conn.Write([]byte{3, 0, 0, 5, 0})
		waitAttack(t, it.sink)
	})
	t.Run("lying parameter length", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "s7comm", buildS7)
		conn := dialTrap(t, it.addr)
		pdu := []byte{s7ProtocolID, s7Job, 0, 0, 0, 1, 0xFF, 0xFF, 0, 0}
		_, _ = conn.Write(s7TPKT(append([]byte{0x02, cotpDT, 0x80}, pdu...)))
		readS7(t, conn)
		waitAttack(t, it.sink)
	})
}

func TestS7StopClosesConnection(t *testing.T) {
	t.Parallel()
	it := startICS(t, "s7comm", buildS7)
	conn := dialTrap(t, it.addr)
	_, _ = conn.Write(s7CR())
	readS7(t, conn)
	assertStopClosesConn(t, it, conn)
}

func TestS7PacketLimit(t *testing.T) {
	t.Parallel()
	it := startICS(t, "s7comm", buildS7)
	conn := dialTrap(t, it.addr)
	go func() {
		for range s7MaxPackets + 10 {
			if _, err := conn.Write(s7SetupReq()); err != nil {
				return
			}
		}
	}()
	br := bufio.NewReader(conn)
	n := 0
	for {
		if _, _, err := readTPKT(br); err != nil {
			break
		}
		n++
	}
	if n != s7MaxPackets {
		t.Errorf("answered %d packets, want %d", n, s7MaxPackets)
	}
}

// ---- EtherNet/IP ----

func enipReq(cmd uint16, session uint32, data []byte) []byte {
	b := enipHeader(cmd, session, 0, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, data)
	return b
}

func readENIPResp(t *testing.T, conn net.Conn) enipPacket {
	t.Helper()
	p, err := readENIP(conn)
	if err != nil {
		t.Fatalf("read enip: %v", err)
	}
	return p
}

func TestENIPProbePath(t *testing.T) {
	t.Parallel()
	it := startICS(t, "enip", buildENIP)
	conn := dialTrap(t, it.addr)

	// NOP is ignored: the next answer belongs to ListIdentity.
	_, _ = conn.Write(enipReq(enipNOP, 0, []byte{1, 2, 3, 4}))
	_, _ = conn.Write(enipReq(enipListIdentity, 0, nil))
	p := readENIPResp(t, conn)
	if p.command != enipListIdentity || p.context != [8]byte{1, 2, 3, 4, 5, 6, 7, 8} {
		t.Fatalf("response = %+v", p)
	}
	if !bytes.Contains(p.data, []byte("1769-L33ER/A LOGIX5333ER")) || binary.LittleEndian.Uint16(p.data[:2]) != 1 {
		t.Errorf("identity data = %x", p.data)
	}

	_, _ = conn.Write(enipReq(enipRegisterSession, 0, []byte{1, 0, 0, 0}))
	p = readENIPResp(t, conn)
	if p.command != enipRegisterSession || p.session != enipSessionHandle {
		t.Errorf("register response = %+v", p)
	}

	_, _ = conn.Write(enipReq(enipListServices, 0, nil))
	if p = readENIPResp(t, conn); !bytes.Contains(p.data, []byte("Communications")) {
		t.Errorf("list services = %x", p.data)
	}
	_, _ = conn.Write(enipReq(enipListInterfaces, 0, nil))
	if p = readENIPResp(t, conn); len(p.data) != 2 {
		t.Errorf("list interfaces = %x", p.data)
	}
	_, _ = conn.Write(enipReq(enipUnRegisterSession, enipSessionHandle, nil))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Errorf("UnRegisterSession should close cleanly: %v", err)
	}

	if got := it.sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("class = %s, want probe", got)
	}
	if hasClass(it.sink.snapshot(), alert.ClassAttack) {
		t.Error("probe path produced an attack")
	}
}

func TestENIPAttackKinds(t *testing.T) {
	t.Parallel()
	cpf := func(item byte) []byte {
		d := []byte{0, 0, 0, 0, 10, 0, 2, 0, 0, 0, 0, 0, 0xB2, 0, 4, 0}
		return append(d, item, 0, 0, 0)
	}
	cases := []struct {
		name string
		cmd  uint16
		data []byte
		kind string
		keys []string
		svc  string
	}{
		{"send rr data", enipSendRRData, cpf(0x4C), enipKindSendData, []string{"kind", "command_code", "cip_service"}, "76"},
		{"send unit data", enipSendUnitData, []byte{1, 2}, enipKindSendData, []string{"kind", "command_code"}, ""},
		{"unknown command", 0x7777, []byte{1}, enipKindUnknown, []string{"kind", "command_code"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			it := startICS(t, "enip", buildENIP)
			conn := dialTrap(t, it.addr)
			_, _ = conn.Write(enipReq(tc.cmd, enipSessionHandle, tc.data))
			p := readENIPResp(t, conn)
			if p.command != tc.cmd || len(p.data) != 0 {
				t.Errorf("response = %+v", p)
			}
			ev := waitAttack(t, it.sink)
			assertMetaKeys(t, ev, tc.keys...)
			if ev.Meta["kind"] != tc.kind || ev.Meta["cip_service"] != tc.svc {
				t.Errorf("meta = %v", ev.Meta)
			}
			if ev.Info.PayloadBytes == 0 {
				t.Errorf("payload bytes = 0")
			}
		})
	}
}

func TestENIPOversizedAndTruncated(t *testing.T) {
	t.Parallel()
	t.Run("oversized length", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "enip", buildENIP)
		conn := dialTrap(t, it.addr)
		h := enipReq(enipSendRRData, 0, nil)
		binary.LittleEndian.PutUint16(h[2:4], enipMaxData+1)
		_, _ = conn.Write(h)
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Errorf("want a clean close: %v", err)
		}
		it.waitOutcomeLabel(t, "enip", outcomeTooLong)
	})
	t.Run("at the limit", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "enip", buildENIP)
		conn := dialTrap(t, it.addr)
		_, _ = conn.Write(enipReq(0x7777, 0, make([]byte, enipMaxData)))
		readENIPResp(t, conn)
		waitAttack(t, it.sink)
	})
	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "enip", buildENIP)
		conn := dialTrap(t, it.addr)
		_, _ = conn.Write(enipReq(enipSendRRData, 0, make([]byte, 40))[:30])
		conn.Close()
		it.waitOutcomeLabel(t, "enip", outcomeError)
		if hasClass(it.sink.snapshot(), alert.ClassAttack) {
			t.Error("truncated packet must not be an attack")
		}
	})
}

func TestENIPCIPServiceBounds(t *testing.T) {
	t.Parallel()
	for _, d := range [][]byte{nil, {1}, make([]byte, 8), {0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xB2, 0, 0xFF, 0xFF}} {
		if got := enipCIPService(enipSendRRData, d); got != -1 {
			t.Errorf("service for %x = %d, want -1", d, got)
		}
	}
	if got := enipCIPService(enipListIdentity, make([]byte, 40)); got != -1 {
		t.Errorf("service for ListIdentity = %d", got)
	}
}

func TestENIPStopClosesConnection(t *testing.T) {
	t.Parallel()
	it := startICS(t, "enip", buildENIP)
	conn := dialTrap(t, it.addr)
	_, _ = conn.Write(enipReq(enipRegisterSession, 0, []byte{1, 0, 0, 0}))
	readENIPResp(t, conn)
	assertStopClosesConn(t, it, conn)
}
