package trap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// Limits for client-controlled RESP sizes; nothing is allocated beyond them.
const (
	maxRESPArgs = 128
	maxRESPBulk = 4096
)

type RedisTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewRedis(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *RedisTrap {
	t := &RedisTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
	}
	t.tcpServer = newTCPServer("redis", cfg, logger, m, limiter, alerter, t.handle)
	return t
}

func (t *RedisTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	reader := bufio.NewReaderSize(conn, 4096)

	for {
		args, err := readRedisCommand(reader)
		if err != nil {
			setOutcome(sess, err)
			return
		}
		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "AUTH":
			// AUTH <password> or AUTH <username> <password>.
			username, password := "", ""
			switch {
			case len(args) > 2:
				username, password = args[1], args[2]
			case len(args) > 1:
				password = args[1]
			}
			sess.LogAuthAttempt(
				slog.String("username", username),
				slog.String("password", password),
			)
			sess.RecordCredentials(t.metrics)
			meta := map[string]string{}
			if username != "" {
				meta["username"] = username
			}
			sess.Alert(ctx, meta)
			fmt.Fprint(conn, "-ERR invalid password\r\n")

		case "QUIT":
			fmt.Fprint(conn, "+OK\r\n")
			return

		default:
			cmdLine := strings.Join(args, " ")
			sess.LogCommand(cmdLine)
			sess.AlertCommand(ctx, cmdLine)
			fmt.Fprint(conn, "-NOAUTH Authentication required.\r\n")
		}
	}
}

func readRedisCommand(reader *bufio.Reader) ([]string, error) {
	b, err := reader.Peek(1)
	if err != nil {
		return nil, err
	}

	if b[0] == '*' {
		return readRESPArray(reader)
	}
	return readInlineCommand(reader)
}

func readRESPArray(reader *bufio.Reader) ([]string, error) {
	line, err := readLineLimited(reader, maxLineLen)
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")

	count, err := strconv.Atoi(line[1:])
	if err != nil || count < 0 {
		return nil, fmt.Errorf("invalid RESP array count: %s", line)
	}

	if count > maxRESPArgs {
		return nil, fmt.Errorf("RESP array too large: %d", count)
	}

	// Never preallocate from the client-supplied count.
	var args []string
	for i := 0; i < count; i++ {
		header, err := readLineLimited(reader, maxLineLen)
		if err != nil {
			return nil, err
		}
		header = strings.TrimRight(header, "\r\n")
		if len(header) == 0 || header[0] != '$' {
			return nil, fmt.Errorf("expected bulk string, got: %s", header)
		}
		length, err := strconv.Atoi(header[1:])
		if err != nil || length < 0 || length > maxRESPBulk {
			return nil, fmt.Errorf("invalid bulk string length: %s", header)
		}

		data := make([]byte, length+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		args = append(args, string(data[:length]))
	}
	return args, nil
}

func readInlineCommand(reader *bufio.Reader) ([]string, error) {
	line, err := readLineLimited(reader, maxLineLen)
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, nil
	}
	return strings.Fields(line), nil
}
