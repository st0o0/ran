package trap

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func buildTelnetTrap(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewTelnet(c, l, m, lim, r)
}

func TestParseTelnetIACTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      []byte
		clean   string
		replies []byte
		ttype   string
	}{
		{"plain", []byte("root\r\n"), "root\r\n", nil, ""},
		{"will ttype", []byte("\xff\xfb\x18root\r\n"), "root\r\n", []byte{255, 254, 24}, ""},
		{"do echo", []byte("\xff\xfd\x01x"), "x", []byte{255, 252, 1}, ""},
		{"dont and wont need no answer", []byte("\xff\xfe\x01\xff\xfc\x03a"), "a", nil, ""},
		{"escaped iac", []byte("a\xff\xffb"), "a\xffb", nil, ""},
		{"two byte command", []byte("a\xff\xf1b"), "ab", nil, ""},
		{"ttype is", []byte("\xff\xfa\x18\x00xterm\xff\xf0ok"), "ok", nil, "xterm"},
		{"ttype send is ignored", []byte("\xff\xfa\x18\x01\xff\xf0ok"), "ok", nil, ""},
		{"other subnegotiation", []byte("\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0ok"), "ok", nil, ""},
		{"ttype bounded", append(append([]byte("\xff\xfa\x18\x00"), bytes.Repeat([]byte("A"), 500)...), 255, 240), "", nil, strings.Repeat("A", 64)},
		{"ttype control bytes dropped", []byte("\xff\xfa\x18\x00x\x01\x1b[y\xff\xf0"), "", nil, "x[y"},
		{"truncated option", []byte("ab\xff\xfb"), "ab", nil, ""},
		{"truncated iac", []byte("ab\xff"), "ab", nil, ""},
		{"unterminated subneg", []byte("ab\xff\xfa\x18\x00xterm"), "ab", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clean, replies, ttype := parseTelnetIAC(tc.in)
			if string(clean) != tc.clean {
				t.Errorf("clean = %q, want %q", clean, tc.clean)
			}
			if !bytes.Equal(replies, tc.replies) {
				t.Errorf("replies = %v, want %v", replies, tc.replies)
			}
			if ttype != tc.ttype {
				t.Errorf("ttype = %q, want %q", ttype, tc.ttype)
			}
		})
	}
}

func TestParseTelnetIACLongRuns(t *testing.T) {
	t.Parallel()
	in := bytes.Repeat([]byte{255, 253, 1}, 4000)
	clean, replies, _ := parseTelnetIAC(in)
	if len(clean) != 0 {
		t.Errorf("clean = %d bytes, want 0", len(clean))
	}
	if len(replies) > maxTelnetReplyBytes {
		t.Errorf("replies = %d bytes, want at most %d", len(replies), maxTelnetReplyBytes)
	}
	clean, _, _ = parseTelnetIAC(bytes.Repeat([]byte{255}, 4001))
	if len(clean) != 2000 {
		t.Errorf("escaped run clean = %d bytes, want 2000", len(clean))
	}
}

func TestTelnetMiraiStyleClient(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "telnet", nil, buildTelnetTrap)
	conn := dialTrap(t, d.addr)

	buf := make([]byte, 64)
	_, _ = conn.Read(buf) // "\r\nLogin: "
	_, _ = conn.Write([]byte("\xff\xfb\x18\xff\xfd\x01root\r\n"))
	var got []byte // negotiation replies and the password prompt
	for !bytes.Contains(got, []byte("Password:")) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	for _, want := range [][]byte{{255, 254, 24}, {255, 252, 1}} {
		if !bytes.Contains(got, want) {
			t.Errorf("reply %v lacks %v", got, want)
		}
	}
	_, _ = conn.Write([]byte("\xff\xfc\x03toor\r\n"))
	d.waitCredentials(t, "telnet", 1)
	evs := d.sink.waitEvents(t, func(e []alert.Event) bool { return len(e) > 0 })
	if evs[0].Meta["username"] != "root" || evs[0].Meta["password"] != "toor" {
		t.Errorf("meta = %v", evs[0].Meta)
	}
	if strings.Contains(d.logs.String(), `ÿ`) || strings.Contains(d.logs.String(), "\xff") {
		t.Errorf("IAC byte leaked into the log:\n%s", d.logs.String())
	}
}

func TestTelnetTerminalTypeLogged(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "telnet", nil, buildTelnetTrap)
	conn := dialTrap(t, d.addr)
	buf := make([]byte, 64)
	_, _ = conn.Read(buf)
	_, _ = conn.Write([]byte("\xff\xfa\x18\x00xterm\xff\xf0root\r\n"))
	_, _ = conn.Write([]byte("pw\r\n"))
	d.waitCredentials(t, "telnet", 1)
	if !strings.Contains(d.logs.String(), `"terminal_type":"xterm"`) {
		t.Errorf("terminal type not logged:\n%s", d.logs.String())
	}
}

func TestTelnetTruncatedSequenceEndsNormally(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "telnet", nil, buildTelnetTrap)
	conn := dialTrap(t, d.addr)
	buf := make([]byte, 64)
	_, _ = conn.Read(buf)
	_, _ = conn.Write([]byte("root\xff\xfb\n"))
	_, _ = conn.Read(buf)
	_, _ = conn.Write([]byte("pw\xff\n"))
	d.waitCredentials(t, "telnet", 1)
	conn.Close()
	d.waitOutcomeLabel(t, "telnet", "completed")
	evs := d.sink.waitEvents(t, func(e []alert.Event) bool { return len(e) > 0 })
	if evs[0].Meta["username"] != "root" || evs[0].Meta["password"] != "pw" {
		t.Errorf("meta = %v", evs[0].Meta)
	}
}

func TestTelnetSilentAfterNegotiationTimesOut(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "telnet", func(c *config.Config) { c.SessionTimeout = 300 * time.Millisecond }, buildTelnetTrap)
	conn := dialTrap(t, d.addr)
	_, _ = io.ReadFull(conn, make([]byte, 9))
	d.waitOutcomeLabel(t, "telnet", "timeout")
}
