package trap

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type PostgresTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewPostgres(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *PostgresTrap {
	t := &PostgresTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("postgres", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *PostgresTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	startup, err := readPgStartupMessage(conn)
	if err != nil {
		setOutcome(sess, err)
		return
	}

	if len(startup) == 4 && binary.BigEndian.Uint32(startup) == 80877103 {
		_, _ = conn.Write([]byte{'N'})
		startup, err = readPgStartupMessage(conn)
		if err != nil {
			setOutcome(sess, err)
			return
		}
	}

	username := parsePgStartupParams(startup)

	maxRetries := t.cfg.ResolveMaxAuthRetries("postgres")
	authDelay := t.cfg.ResolveAuthDelay("postgres")

	// Every iteration blocks on a client read (bounded by the session deadline)
	// and, with an auth delay, on authSleep, so unlimited retries cannot spin.
	prev := ""
	for attempt := 0; maxRetries == 0 || attempt < maxRetries; attempt++ {
		// AuthenticationCleartextPassword. A rejected password is followed by a
		// new request on the same connection (no error in between), so a client
		// that keeps sending password messages can try several passwords.
		var auth [9]byte
		auth[0] = 'R'
		binary.BigEndian.PutUint32(auth[1:5], 8)
		binary.BigEndian.PutUint32(auth[5:9], 3)
		if _, err := conn.Write(auth[:]); err != nil {
			sess.setReadOutcome(err)
			return
		}

		password, err := readPgPasswordMessage(conn)
		if err != nil {
			sess.setReadOutcome(err)
			return
		}

		// libpq and pgx answer a repeated request with the same stored
		// password. That is not a new attempt: end the session instead of
		// logging it again.
		if attempt > 0 && password == prev {
			break
		}
		prev = password

		sess.Cred(ctx, t.metrics, username, password)

		if authDelay > 0 {
			if err := sess.authSleep(ctx, authDelay, attempt); err != nil {
				sess.SetOutcome("timeout")
				return
			}
		}
	}

	errMsg := fmt.Sprintf("password authentication failed for user \"%s\"", username)
	writePgErrorResponse(conn, errMsg)
}

func readPgStartupMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(lenBuf[:]))
	if length < 4 || length > 1<<20 {
		return nil, fmt.Errorf("invalid startup length: %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func parsePgStartupParams(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	params := data[4:]
	for len(params) > 1 {
		keyEnd := 0
		for keyEnd < len(params) && params[keyEnd] != 0 {
			keyEnd++
		}
		if keyEnd >= len(params) {
			break
		}
		key := string(params[:keyEnd])
		params = params[keyEnd+1:]

		valEnd := 0
		for valEnd < len(params) && params[valEnd] != 0 {
			valEnd++
		}
		if valEnd >= len(params) {
			break
		}
		val := string(params[:valEnd])
		params = params[valEnd+1:]

		if key == "user" {
			return val
		}
	}
	return ""
}

func readPgPasswordMessage(r io.Reader) (string, error) {
	var tag [1]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return "", err
	}
	if tag[0] != 'p' {
		return "", fmt.Errorf("expected password message, got %c", tag[0])
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	length := int(binary.BigEndian.Uint32(lenBuf[:]))
	if length < 4 || length > 1<<20 {
		return "", fmt.Errorf("invalid password length: %d", length)
	}
	data := make([]byte, length-4)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	return string(data), nil
}

func writePgErrorResponse(w io.Writer, msg string) {
	var body []byte
	body = append(body, 'S')
	body = append(body, "FATAL\x00"...)
	body = append(body, 'M')
	body = append(body, msg...)
	body = append(body, 0)
	body = append(body, 0)

	var pkt []byte
	pkt = append(pkt, 'E')
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)+4))
	pkt = append(pkt, lenBuf[:]...)
	pkt = append(pkt, body...)
	_, _ = w.Write(pkt)
}
