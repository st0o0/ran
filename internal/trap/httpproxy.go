package trap

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type HTTPProxyTrap struct {
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	limiter *Limiter
	alerter alert.Alerter
	srv     *http.Server
	wg      sync.WaitGroup
}

func NewHTTPProxy(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *HTTPProxyTrap {
	t := &HTTPProxyTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}

	addr := cfg.TrapAddr("httpproxy")
	t.srv = &http.Server{
		Addr:         addr,
		Handler:      t,
		ReadTimeout:  cfg.SessionTimeout,
		WriteTimeout: cfg.SessionTimeout,
	}
	return t
}

func (t *HTTPProxyTrap) Start(ctx context.Context) error {
	addr := t.cfg.TrapAddr("httpproxy")
	ln, err := ListenTCP(ctx, addr, t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("httpproxy listen: %w", err)
	}
	t.logger.Info("listening", "addr", addr)

	go func() {
		<-ctx.Done()
		t.srv.Close()
	}()

	if err := t.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (t *HTTPProxyTrap) Stop(ctx context.Context) error {
	t.srv.Close()
	t.wg.Wait()
	return nil
}

func (t *HTTPProxyTrap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, port := ParseAddr(r.RemoteAddr)
	_, destPort := ParseAddr(t.cfg.TrapAddr("httpproxy"))
	sess := NewSession("httpproxy", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		t.logger.Warn("connection rejected", "source_ip", host, "reason", "limit_exceeded")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	if authHeader := r.Header.Get("Proxy-Authorization"); authHeader != "" {
		t.handleProxyAuth(sess, r, host, authHeader)
	}

	if r.Method == http.MethodConnect {
		sess.LogCommand("CONNECT "+r.Host)
		t.alerter.Alert(r.Context(), host, "httpproxy", map[string]string{"command": "CONNECT " + r.Host})
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	if r.URL.Host != "" {
		sess.LogCommand(r.Method+" "+r.URL.String())
		t.alerter.Alert(r.Context(), host, "httpproxy", map[string]string{"command": r.Method + " " + r.URL.String()})
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	http.Error(w, "Bad Request", http.StatusBadRequest)
}

func (t *HTTPProxyTrap) handleProxyAuth(sess *Session, r *http.Request, host, authHeader string) {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return
	}

	sess.LogAuthAttempt(
		slog.String("username", creds[0]),
		slog.String("password", creds[1]),
	)
	sess.RecordCredentials(t.metrics)
	t.alerter.Alert(r.Context(), host, "httpproxy", map[string]string{"username": creds[0], "password": creds[1]})
}
