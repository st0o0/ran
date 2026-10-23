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

type MemcachedTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewMemcached(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *MemcachedTrap {
	t := &MemcachedTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("memcached", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *MemcachedTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.ToLower(strings.TrimSpace(line)) == "quit" {
			return
		}
		sess.LogCommand(line)
		sess.AlertCommand(ctx, line)
		fmt.Fprint(conn, "ERROR\r\n")
	}
	if err := scanner.Err(); err != nil {
		setOutcome(sess, err)
	}
}
