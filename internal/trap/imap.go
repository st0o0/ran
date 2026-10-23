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

type IMAPTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewIMAP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *IMAPTrap {
	t := &IMAPTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("imap", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *IMAPTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	if _, err := fmt.Fprint(conn, "* OK IMAP4rev1 Server Ready\r\n"); err != nil {
		setOutcome(sess, err)
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		cmd := strings.ToUpper(parts[1])
		rest := ""
		if len(parts) > 2 {
			rest = parts[2]
		}

		switch cmd {
		case "LOGIN":
			fields := strings.SplitN(rest, " ", 2)
			username := ""
			password := ""
			if len(fields) >= 1 {
				username = strings.Trim(fields[0], "\"")
			}
			if len(fields) >= 2 {
				password = strings.Trim(fields[1], "\"")
			}
			sess.Cred(ctx, t.metrics, username, password)
			fmt.Fprintf(conn, "%s NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", tag)

		case "CAPABILITY":
			fmt.Fprintf(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN STARTTLS\r\n%s OK CAPABILITY completed\r\n", tag)

		case "LOGOUT":
			fmt.Fprintf(conn, "* BYE IMAP4rev1 Server logging out\r\n%s OK LOGOUT completed\r\n", tag)
			return

		case "NOOP":
			fmt.Fprintf(conn, "%s OK NOOP completed\r\n", tag)

		default:
			sess.LogCommand(line)
			sess.AlertCommand(ctx, cmd)
			fmt.Fprintf(conn, "%s BAD Unknown command\r\n", tag)
		}
	}
	if err := scanner.Err(); err != nil {
		setOutcome(sess, err)
	}
}
