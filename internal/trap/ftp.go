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

type FTPTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewFTP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *FTPTrap {
	t := &FTPTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("ftp", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *FTPTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	if _, err := fmt.Fprint(conn, "220 FTP Server ready.\r\n"); err != nil {
		setOutcome(sess, err)
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 512), 512)
	var username string

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "USER "):
			username = strings.TrimSpace(line[5:])
			fmt.Fprint(conn, "331 Password required.\r\n")

		case strings.HasPrefix(upper, "PASS "):
			password := strings.TrimSpace(line[5:])
			sess.Cred(ctx, t.metrics, username, password)
			fmt.Fprint(conn, "530 Login incorrect.\r\n")

		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(conn, "221 Goodbye.\r\n")
			return

		default:
			fmt.Fprint(conn, "530 Please login with USER and PASS.\r\n")
		}
	}
	if err := scanner.Err(); err != nil {
		setOutcome(sess, err)
	}
}
