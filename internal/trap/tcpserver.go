package trap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// tcpHandler serves one TCP connection. The session is prepared by the
// skeleton (sensor wired, deadline set, start and end recorded); the handler
// only speaks the protocol. The connection is closed when it returns.
type tcpHandler func(ctx context.Context, conn net.Conn, sess *Session)

// bound publishes the address a trap listens on, mainly so tests can use port 0.
type bound struct {
	once sync.Once
	ch   chan struct{}
	addr net.Addr
}

func newBound() *bound { return &bound{ch: make(chan struct{})} }

func (b *bound) set(addr net.Addr) {
	b.once.Do(func() {
		b.addr = addr
		close(b.ch)
	})
}

// Ready is closed once the trap listens.
func (b *bound) Ready() <-chan struct{} { return b.ch }

// Addr returns the first listen address, or nil before Ready is closed.
func (b *bound) Addr() net.Addr {
	select {
	case <-b.ch:
		return b.addr
	default:
		return nil
	}
}

// tcpServer is the shared accept and session skeleton of all raw TCP traps.
// It owns listening (PROXY protocol, accept backoff), the limiter, session
// setup and metrics, panic safety and shutdown. Traps embed it and provide a
// tcpHandler.
type tcpServer struct {
	*bound

	proto    string
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	reporter Reporter
	handler  tcpHandler

	mu       sync.Mutex
	ln       *MultiListener
	conns    map[net.Conn]context.CancelFunc
	stopping bool
	wg       sync.WaitGroup
}

func newTCPServer(proto string, cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, reporter Reporter, handler tcpHandler) *tcpServer {
	return &tcpServer{
		bound:    newBound(),
		proto:    proto,
		cfg:      cfg,
		logger:   logger,
		metrics:  m,
		limiter:  limiter,
		reporter: reporter,
		handler:  handler,
		conns:    make(map[net.Conn]context.CancelFunc),
	}
}

// Start listens and serves until ctx is cancelled or Stop is called. Cancelling
// ctx also closes live connections.
func (s *tcpServer) Start(ctx context.Context) error {
	addrs := s.cfg.TrapAddrs(s.proto)
	ln, err := ListenMultiTCP(ctx, addrs, s.cfg.ProxyProtocol, s.logger, s.metrics, s.proto)
	if err != nil {
		return fmt.Errorf("%s listen: %w", s.proto, err)
	}

	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		// Close Ready anyway, so a caller waiting for it does not hang.
		s.set(ln.Addr())
		ln.Close()
		return nil
	}
	s.ln = ln
	s.mu.Unlock()

	s.set(ln.Addr())
	s.logger.Info("listening", "addrs", addrs)

	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			LogErrorStandalone(s.logger, s.proto, "accept_failed", err)
			continue
		}
		safely(s.logger, s.metrics, s.proto, func() { s.dispatch(ctx, conn) })
	}
}

// dispatch admits one accepted connection. The limiter slot is taken before the
// goroutine exists, so a flood cannot create more goroutines than the limiter
// allows, and wg.Add happens under the mutex that Stop uses to set stopping.
func (s *tcpServer) dispatch(ctx context.Context, conn net.Conn) {
	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())

	if ctx.Err() != nil {
		conn.Close()
		return
	}
	if !s.limiter.Acquire(host) {
		LogRejected(s.logger, s.metrics, s.proto, alert.TransportTCP, destPort, host, "rate_limit")
		conn.Close()
		return
	}

	connCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		cancel()
		s.limiter.Release(host)
		conn.Close()
		return
	}
	s.conns[conn] = cancel
	s.wg.Add(1)
	s.mu.Unlock()

	go s.serve(connCtx, cancel, conn, host, port, destPort)
}

func (s *tcpServer) serve(ctx context.Context, cancel context.CancelFunc, conn net.Conn, host string, port, destPort int) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	defer s.limiter.Release(host)
	defer cancel()
	defer conn.Close()
	// Cancelling ctx (shutdown) closes the connection, which unblocks any read.
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()

	safely(s.logger, s.metrics, s.proto, func() {
		sess := NewSession(s.proto, alert.TransportTCP, host, port, destPort, s.logger)
		sess.Sensor = s.reporter

		sess.LogConnect()
		sess.RecordStart(s.metrics)
		defer sess.RecordEnd(s.metrics)
		defer sess.LogDisconnect()

		_ = conn.SetDeadline(deadlineFromContext(ctx, s.cfg.ResolveSessionTimeout(s.proto)))
		s.handler(ctx, conn, sess)
	})
}

// Stop closes the listener and every live connection, then waits for the
// workers. It returns ctx.Err() if they do not finish before ctx ends and may
// be called repeatedly.
func (s *tcpServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	ln := s.ln
	cancels := make([]context.CancelFunc, 0, len(s.conns))
	conns := make([]net.Conn, 0, len(s.conns))
	for c, cancel := range s.conns {
		conns = append(conns, c)
		cancels = append(cancels, cancel)
	}
	s.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	for i, c := range conns {
		cancels[i]()
		_ = c.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
