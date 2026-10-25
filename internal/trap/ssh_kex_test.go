package trap

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/metrics"
	"log/slog"

	gossh "golang.org/x/crypto/ssh"
)

func startSSHForKex(t *testing.T) string {
	t.Helper()
	cfg := testConfig(t)
	trap, err := NewSSH(cfg, slog.Default(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return serveTrap(t, ctx, trap)
}

// serverKexInit connects, reads the identification line and the server's
// unencrypted KEXINIT and returns its first four name-lists (kex, host key,
// ciphers c2s, ciphers s2c) and the MAC list c2s.
func serverKexInit(t *testing.T, addr string) (lists []string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("SSH-2.0-test\r\n")); err != nil {
		t.Fatal(err)
	}
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint32(hdr[:4]))
	if n < 2 || n > 1<<16 {
		t.Fatalf("implausible packet length %d", n)
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatal(err)
	}
	if body[0] != sshMsgKexInit {
		t.Fatalf("first packet type %d, want KEXINIT", body[0])
	}
	pos := 1 + 16
	for range 5 { // kex, host key, enc c2s, enc s2c, mac c2s
		l := int(binary.BigEndian.Uint32(body[pos : pos+4]))
		pos += 4
		lists = append(lists, string(body[pos:pos+l]))
		pos += l
	}
	return lists
}

func TestSSHServerKexInitIsEraAppropriate(t *testing.T) {
	t.Parallel()
	lists := serverKexInit(t, startSSHForKex(t))
	kex, hostKey, ciphers, macs := lists[0], lists[1], lists[2], lists[4]
	for _, l := range lists {
		if strings.Contains(l, "mlkem") || strings.Contains(l, "sntrup") {
			t.Errorf("list %q offers an algorithm newer than OpenSSH 9.6 profiles", l)
		}
	}
	for _, want := range []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256"} {
		if !slices.Contains(strings.Split(kex, ","), want) {
			t.Errorf("kex list %q lacks %s", kex, want)
		}
	}
	if !strings.HasPrefix(kex, "curve25519-sha256,") {
		t.Errorf("kex list %q does not start with curve25519-sha256", kex)
	}
	if hostKey != "ssh-ed25519" {
		t.Errorf("host key algorithms = %q, want ssh-ed25519 only", hostKey)
	}
	if !strings.HasPrefix(ciphers, "chacha20-poly1305@openssh.com,") || !strings.Contains(macs, "hmac-sha2-256-etm@openssh.com") {
		t.Errorf("ciphers %q macs %q", ciphers, macs)
	}
}

func TestSSHHandshakeStillCompletesWithRestrictedKex(t *testing.T) {
	t.Parallel()
	addr := startSSHForKex(t)
	for _, kex := range []string{gossh.KeyExchangeCurve25519, gossh.KeyExchangeECDHP256, gossh.KeyExchangeDHGEXSHA256, gossh.KeyExchangeDH14SHA256, gossh.KeyExchangeDH16SHA512} {
		_, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
			User:            "root",
			Auth:            []gossh.AuthMethod{gossh.Password("x")},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
			Config:          gossh.Config{KeyExchanges: []string{kex}},
		})
		// The handshake completed when the failure is the rejected password.
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			t.Errorf("kex %s: err = %v, want an authentication failure after the handshake", kex, err)
		}
	}
	// A client that insists on the hybrid post-quantum KEX finds no common one.
	_, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password("x")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
		Config:          gossh.Config{KeyExchanges: []string{gossh.KeyExchangeMLKEM768X25519}},
	})
	if err == nil || strings.Contains(err.Error(), "unable to authenticate") {
		t.Errorf("mlkem-only client: err = %v, want a handshake failure", err)
	}
}
