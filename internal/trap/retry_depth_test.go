package trap

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func buildMySQLTrap(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewMySQL(c, l, m, lim, r)
}

func buildPostgresTrap(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewPostgres(c, l, m, lim, r)
}

func buildRDPTrap(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewRDP(c, l, m, lim, r)
}

func unlimitedRetries(proto string) func(*config.Config) {
	return func(c *config.Config) {
		zero := 0
		c.PerProto[proto] = config.ProtoConfig{MaxAuthRetries: &zero}
	}
}

func readMySQLFrame(t *testing.T, conn net.Conn) (seq byte, payload []byte) {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read mysql header: %v", err)
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload = make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read mysql payload: %v", err)
	}
	return hdr[3], payload
}

func mysqlLoginPacket(user, password string) []byte {
	var resp []byte
	resp = binary.LittleEndian.AppendUint32(resp, 0x000FA68D)
	resp = binary.LittleEndian.AppendUint32(resp, 1<<24)
	resp = append(resp, 0x21)
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, []byte(user+"\x00")...)
	resp = append(resp, byte(len(password)))
	resp = append(resp, []byte(password)...)
	return wrapMySQLPacket(1, resp)
}

func TestMySQLRetriesViaAuthSwitch(t *testing.T) {
	t.Parallel()
	for _, retries := range []int{1, 2, 3} {
		d := startDepthTrap(t, "mysql", func(c *config.Config) { c.MaxAuthRetries = retries }, buildMySQLTrap)
		conn := dialTrap(t, d.addr)
		readMySQLFrame(t, conn) // greeting
		_, _ = conn.Write(mysqlLoginPacket("root", "pw0"))
		seq := byte(1)
		for attempt := 1; attempt < retries; attempt++ {
			s, payload := readMySQLFrame(t, conn)
			if payload[0] != 0xFE || s != seq+1 {
				t.Fatalf("retries=%d attempt %d: want auth switch seq %d, got 0x%02x seq %d", retries, attempt, seq+1, payload[0], s)
			}
			seq += 2
			_, _ = conn.Write(wrapMySQLPacket(seq, []byte("pw"+strconv.Itoa(attempt)+"\x00")))
		}
		s, payload := readMySQLFrame(t, conn)
		if payload[0] != 0xFF || s != seq+1 {
			t.Errorf("retries=%d: final packet 0x%02x seq %d, want ERR seq %d", retries, payload[0], s, seq+1)
		}
		// The connection is closed after the last attempt.
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Errorf("retries=%d: connection still open", retries)
		}
		d.waitCredentials(t, "mysql", float64(retries))
		time.Sleep(20 * time.Millisecond)
		if got := d.credentials("mysql"); got != float64(retries) {
			t.Errorf("retries=%d: credentials = %v", retries, got)
		}
		d.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	}
}

func TestMySQLUnlimitedRetries(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "mysql", unlimitedRetries("mysql"), buildMySQLTrap)
	conn := dialTrap(t, d.addr)
	readMySQLFrame(t, conn)
	_, _ = conn.Write(mysqlLoginPacket("root", "pw"))
	seq := byte(1)
	for range 10 {
		_, payload := readMySQLFrame(t, conn)
		if payload[0] != 0xFE {
			t.Fatalf("got 0x%02x, want auth switch", payload[0])
		}
		seq += 2
		_, _ = conn.Write(wrapMySQLPacket(seq, []byte("x\x00")))
	}
	d.waitCredentials(t, "mysql", 11)
}

func TestMySQLRetryPasswordParsing(t *testing.T) {
	t.Parallel()
	if got := parseAuthSwitchReply([]byte("secret\x00")); got != "secret" {
		t.Errorf("got %q", got)
	}
	if got := parseAuthSwitchReply(nil); got != "" {
		t.Errorf("got %q", got)
	}
	if got := parseAuthSwitchReply(make([]byte, 100000)); len(got) > maxMySQLPassword {
		t.Errorf("password is %d bytes, want at most %d", len(got), maxMySQLPassword)
	}
}

func TestMySQLRetryClientHangsUpIsCompleted(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "mysql", nil, buildMySQLTrap)
	conn := dialTrap(t, d.addr)
	readMySQLFrame(t, conn)
	_, _ = conn.Write(mysqlLoginPacket("root", "pw"))
	readMySQLFrame(t, conn) // auth switch
	conn.Close()
	d.waitOutcomeLabel(t, "mysql", "completed")
}

func TestMySQLRetryTimeout(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "mysql", func(c *config.Config) { c.SessionTimeout = 300 * time.Millisecond }, buildMySQLTrap)
	conn := dialTrap(t, d.addr)
	readMySQLFrame(t, conn)
	_, _ = conn.Write(mysqlLoginPacket("root", "pw"))
	readMySQLFrame(t, conn)
	d.waitOutcomeLabel(t, "mysql", "timeout")
}

func pgStartup(conn net.Conn, user string) {
	body := binary.BigEndian.AppendUint32(nil, 196608)
	body = append(body, "user\x00"+user+"\x00\x00"...)
	pkt := binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))
	_, _ = conn.Write(append(pkt, body...))
}

func pgPassword(conn net.Conn, password string) {
	msg := []byte{'p'}
	msg = binary.BigEndian.AppendUint32(msg, uint32(4+len(password)+1))
	msg = append(msg, password...)
	msg = append(msg, 0)
	_, _ = conn.Write(msg)
}

func TestPostgresRetriesAskAgain(t *testing.T) {
	t.Parallel()
	for _, retries := range []int{1, 2, 3} {
		d := startDepthTrap(t, "postgres", func(c *config.Config) { c.MaxAuthRetries = retries }, buildPostgresTrap)
		conn := dialTrap(t, d.addr)
		pgStartup(conn, "admin")
		for attempt := 0; attempt < retries; attempt++ {
			auth := make([]byte, 9)
			if _, err := io.ReadFull(conn, auth); err != nil {
				t.Fatalf("retries=%d attempt %d: %v", retries, attempt, err)
			}
			if auth[0] != 'R' || binary.BigEndian.Uint32(auth[5:9]) != 3 {
				t.Fatalf("retries=%d attempt %d: got %v, want cleartext password request", retries, attempt, auth)
			}
			pgPassword(conn, "pw")
		}
		tag := make([]byte, 1)
		if _, err := io.ReadFull(conn, tag); err != nil || tag[0] != 'E' {
			t.Errorf("retries=%d: final tag %q err %v, want E", retries, tag, err)
		}
		d.waitCredentials(t, "postgres", float64(retries))
		d.sink.waitEvents(t, func(e []alert.Event) bool { return hasClass(e, alert.ClassAttack) })
	}
}

func TestPostgresUnlimitedRetries(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "postgres", unlimitedRetries("postgres"), buildPostgresTrap)
	conn := dialTrap(t, d.addr)
	pgStartup(conn, "admin")
	for range 10 {
		if _, err := io.ReadFull(conn, make([]byte, 9)); err != nil {
			t.Fatal(err)
		}
		pgPassword(conn, "pw")
	}
	d.waitCredentials(t, "postgres", 10)
}

func TestPostgresRetryAuthDelayThenTimeout(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "postgres", func(c *config.Config) {
		c.SessionTimeout = 400 * time.Millisecond
		c.AuthDelay = 10 * time.Millisecond
	}, buildPostgresTrap)
	conn := dialTrap(t, d.addr)
	pgStartup(conn, "admin")
	_, _ = io.ReadFull(conn, make([]byte, 9))
	pgPassword(conn, "pw")
	d.waitOutcomeLabel(t, "postgres", "timeout")
}

// rdp stays a single attempt per TCP session: after the negotiation failure the
// connection ends, whatever RAN_MAX_AUTH_RETRIES says.
func TestRDPStaysSingleAttempt(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "rdp", func(c *config.Config) { c.MaxAuthRetries = 5 }, buildRDPTrap)
	conn := dialTrap(t, d.addr)
	_, _ = conn.Write(buildRDPConnectionRequest("administrator"))
	resp := make([]byte, 19)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(buildRDPConnectionRequest("second"))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after the negotiation failure")
	}
	d.waitCredentials(t, "rdp", 1)
	time.Sleep(20 * time.Millisecond)
	if got := d.credentials("rdp"); got != 1 {
		t.Errorf("credentials = %v, want 1", got)
	}
}
