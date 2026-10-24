package trap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	// catchallMaxBytes is the most the trap ever reads from a connection.
	catchallMaxBytes = 256
	// catchallReadWindow is how long the trap waits for the first bytes. It is cut
	// to the session deadline, so it never exceeds RAN_SESSION_TIMEOUT.
	catchallReadWindow = 3 * time.Second
)

// Labels of the protocol sniffer. The set is fixed; the label is never derived
// from client data.
const (
	sniffTLS     = "tls"
	sniffHTTP    = "http"
	sniffSMB     = "smb"
	sniffSSH     = "ssh"
	sniffRDP     = "rdp"
	sniffUnknown = "unknown"
)

var httpMethodPrefixes = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("CONNECT "), []byte("TRACE "), []byte("PATCH "),
	[]byte("PROPFIND "), []byte("PRI * HTTP/2.0"),
}

// sniffProtocol labels the first bytes of a connection as one of tls, http, smb,
// ssh, rdp or unknown (also for empty input). It only looks at fixed positions
// and never allocates from the input.
func sniffProtocol(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("SSH-")):
		return sniffSSH
	case len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04:
		return sniffTLS
	case len(b) >= 8 && b[0] == 0x00 && (bytes.Equal(b[4:8], []byte("\xffSMB")) || bytes.Equal(b[4:8], []byte("\xfeSMB"))):
		return sniffSMB
	case len(b) >= 6 && b[0] == 0x03 && b[1] == 0x00 && b[5] == 0xE0:
		return sniffRDP
	}
	for _, p := range httpMethodPrefixes {
		if bytes.HasPrefix(b, p) {
			return sniffHTTP
		}
	}
	return sniffUnknown
}

// printableText maps every byte outside printable ASCII to '.', so the log text
// is valid UTF-8 with no control characters.
func printableText(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			c = '.'
		}
		out[i] = c
	}
	return string(out)
}

// CatchallTrap accepts TCP connections on operator chosen ports (no default
// port), reads the first bytes once and logs them with a protocol guess. It never
// sends data back.
type CatchallTrap struct {
	*tcpServer
	readWindow time.Duration
}

func NewCatchall(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *CatchallTrap {
	t := &CatchallTrap{readWindow: catchallReadWindow}
	t.tcpServer = newTCPServer("catchall", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *CatchallTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	deadline := time.Now().Add(t.readWindow)
	if !sess.Deadline.IsZero() && sess.Deadline.Before(deadline) {
		deadline = sess.Deadline
	}
	_ = conn.SetReadDeadline(deadline)

	var buf [catchallMaxBytes]byte
	n, err := conn.Read(buf[:])
	if n == 0 {
		// A connect that sends nothing is a probe, whether the window ended or
		// the client closed.
		if err != nil && !isTimeout(err) && !errors.Is(err, io.EOF) {
			setOutcome(sess, err)
			return
		}
		sess.SetOutcome("probe")
		return
	}

	data := buf[:n]
	label := sniffProtocol(data)
	sess.LogPayloadSize("catchall", n,
		slog.String("sniffed_protocol", label),
		slog.Int("bytes", n),
		slog.String("hex", hex.EncodeToString(data)),
		slog.String("text", printableText(data)),
	)
	sess.Alert(ctx, map[string]string{
		"sniffed_protocol": label,
		"bytes":            strconv.Itoa(n),
	})
}
