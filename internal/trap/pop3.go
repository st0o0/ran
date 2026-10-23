package trap

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type POP3Trap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewPOP3(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *POP3Trap {
	t := &POP3Trap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("pop3", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *POP3Trap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	if _, err := fmt.Fprint(conn, "+OK POP3 server ready\r\n"); err != nil {
		setOutcome(sess, err)
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 1024)
	var username string

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "USER "):
			username = strings.TrimSpace(line[5:])
			fmt.Fprint(conn, "+OK\r\n")

		case strings.HasPrefix(upper, "PASS "):
			password := strings.TrimSpace(line[5:])
			sess.Cred(ctx, t.metrics, username, password)
			fmt.Fprint(conn, "-ERR [AUTH] Authentication failed\r\n")

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(conn, "+OK Bye\r\n")
			return

		default:
			fmt.Fprint(conn, "-ERR Unknown command\r\n")
		}
	}
	if err := scanner.Err(); err != nil {
		setOutcome(sess, err)
	}
}
