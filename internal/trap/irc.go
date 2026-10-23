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

type IRCTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewIRC(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *IRCTrap {
	t := &IRCTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("irc", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *IRCTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	host := sess.SourceIP
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 512), 512)
	var nick string
	registered := false

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		params := ""
		if len(parts) > 1 {
			params = parts[1]
		}

		switch cmd {
		case "PASS":
			password := strings.TrimPrefix(params, ":")
			sess.Cred(ctx, t.metrics, nick, password)

		case "NICK":
			nick = strings.TrimPrefix(params, ":")
			if registered {
				continue
			}

		case "USER":
			if !registered {
				registered = true
				if nick == "" {
					nick = "*"
				}
				fmt.Fprintf(conn, ":server 001 %s :Welcome to the IRC Network\r\n", nick)
			}

		case "QUIT":
			fmt.Fprintf(conn, "ERROR :Closing Link: %s (Quit)\r\n", host)
			return

		case "PING":
			fmt.Fprintf(conn, "PONG %s\r\n", params)

		default:
			sess.LogCommand(line)
			sess.AlertCommand(ctx, line)
		}
	}
	if err := scanner.Err(); err != nil {
		setOutcome(sess, err)
	}
}
