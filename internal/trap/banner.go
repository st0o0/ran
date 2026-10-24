package trap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

const (
	// maxBannerLine is the longest client line the banner trap reads.
	maxBannerLine = 512
	// maxBannerLines is the most lines read from one connection; the session ends
	// after that, so a fast client cannot flood the log.
	maxBannerLines = 100
)

// BannerTrap sends a configured banner on connect and logs what the client
// sends, one service per configured port. Each service runs on its own TCP
// skeleton so its banner is fixed by the listener, not looked up from the
// (possibly client controlled) local address. The metrics protocol label is
// always "banner"; the configured name only appears in logs and alert meta.
type BannerTrap struct {
	*bound
	servers []*tcpServer
}

func NewBanner(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) (*BannerTrap, error) {
	return newBanner(cfg, logger, m, limiter, alerter, "")
}

func newBanner(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter, host string) (*BannerTrap, error) {
	if len(cfg.BannerServices) == 0 {
		return nil, fmt.Errorf("no banner services configured; set RAN_BANNER_SERVICES")
	}
	t := &BannerTrap{bound: newBound()}
	for _, svc := range cfg.BannerServices {
		s := newTCPServer("banner", cfg, logger.With("service", sanitizeHTTPValue(svc.Name)), m, limiter, alerter, bannerHandler(svc))
		s.addrs = []string{net.JoinHostPort(host, strconv.Itoa(svc.Port))}
		t.servers = append(t.servers, s)
	}
	return t, nil
}

// Start listens on every service port and serves until ctx ends or Stop is
// called. If one port cannot be bound, all services stop and the error is
// returned.
func (t *BannerTrap) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make([]error, len(t.servers))
	var wg sync.WaitGroup
	for i, s := range t.servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Start(ctx)
			if errs[i] != nil {
				cancel()
			}
		}()
	}
	go func() {
		for _, s := range t.servers {
			select {
			case <-s.Ready():
			case <-ctx.Done():
				return
			}
		}
		t.set(t.servers[0].Addr())
	}()
	wg.Wait()
	return errors.Join(errs...)
}

// Addrs returns the bound address of every service, in configuration order.
func (t *BannerTrap) Addrs() []net.Addr {
	out := make([]net.Addr, len(t.servers))
	for i, s := range t.servers {
		out[i] = s.Addr()
	}
	return out
}

// Stop stops every service; see tcpServer.Stop.
func (t *BannerTrap) Stop(ctx context.Context) error {
	errs := make([]error, len(t.servers))
	var wg sync.WaitGroup
	for i, s := range t.servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Stop(ctx)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func bannerHandler(svc config.BannerService) tcpHandler {
	name := sanitizeHTTPValue(svc.Name)
	return func(ctx context.Context, conn net.Conn, sess *Session) {
		if _, err := conn.Write(svc.Banner); err != nil {
			setOutcome(sess, err)
			return
		}
		reader := bufio.NewReaderSize(conn, 1024)
		alerted := false
		for range maxBannerLines {
			line, err := readLinePartial(reader, maxBannerLine)
			if errors.Is(err, bufio.ErrTooLong) {
				// Bytes were sent but not stored; count them as payload.
				sess.LogPayloadSize("banner_overlong", maxBannerLine+1, slog.String("service", name))
				sess.Alert(ctx, map[string]string{"service": name})
				sess.SetOutcome(outcomeTooLong)
				return
			}
			if cmd := redactSecretHeader(strings.TrimSpace(sanitizeHTTPValue(line))); cmd != "" {
				sess.LogCommand(cmd, slog.String("service", name))
				if !alerted {
					alerted = true
					sess.Alert(ctx, map[string]string{"command": commandName(cmd), "service": name})
				}
			}
			if err != nil {
				switch {
				case sess.commands == 0 && (isTimeout(err) || errors.Is(err, io.EOF)):
					sess.SetOutcome("probe")
				case errors.Is(err, io.EOF):
				default:
					setOutcome(sess, err)
				}
				return
			}
		}
	}
}

// secretHeaders are header names whose value is a credential. A banner service
// may imitate an HTTP-like protocol, so these lines are treated like the
// credential verbs of the other traps (see redactCommand).
var secretHeaders = map[string]bool{"authorization:": true, "proxy-authorization:": true, "cookie:": true}

// redactSecretHeader hides the value of a credential header according to
// RAN_LOG_PASSWORDS (on keeps it, mask shows its length, off drops it). Other
// lines pass through; LogCommand still hides known credential verbs.
func redactSecretHeader(line string) string {
	if passwordMode.Load() == passwordsOn {
		return line
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 && secretHeaders[strings.ToLower(fields[0])] {
		return redactTail(fields, 1)
	}
	return line
}
