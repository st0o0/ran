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

type TelnetTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewTelnet(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *TelnetTrap {
	t := &TelnetTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("telnet", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *TelnetTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	reader := bufio.NewReaderSize(conn, 4096)
	maxRetries := t.cfg.ResolveMaxAuthRetries("telnet")
	authDelay := t.cfg.ResolveAuthDelay("telnet")

	for attempt := 0; maxRetries == 0 || attempt < maxRetries; attempt++ {
		fmt.Fprint(conn, "\r\nLogin: ")
		username, err := t.readTelnetField(conn, reader, sess)
		if err != nil {
			sess.setReadOutcome(err)
			return
		}

		fmt.Fprint(conn, "Password: ")
		password, err := t.readTelnetField(conn, reader, sess)
		if err != nil {
			sess.setReadOutcome(err)
			return
		}

		sess.Cred(ctx, t.metrics, username, password)

		if authDelay > 0 {
			if err := authSleep(ctx, authDelay, attempt); err != nil {
				sess.SetOutcome("timeout")
				return
			}
		}

		fmt.Fprint(conn, "\r\nLogin incorrect\r\n")
	}
}

// readTelnetField reads one input line, answers its option negotiation and
// returns the text without IAC sequences. The terminal type, if reported, is
// logged as a probe event.
func (t *TelnetTrap) readTelnetField(conn net.Conn, reader *bufio.Reader, sess *Session) (string, error) {
	line, err := readLineLimited(reader, maxLineLen)
	if err != nil {
		return "", err
	}
	clean, replies, ttype := parseTelnetIAC([]byte(line))
	if len(replies) > 0 {
		_, _ = conn.Write(replies)
	}
	if ttype != "" {
		sess.Log("telnet_terminal_type", slog.String("terminal_type", ttype))
	}
	return strings.TrimSpace(string(clean)), nil
}
