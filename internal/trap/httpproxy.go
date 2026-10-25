package trap

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type HTTPProxyTrap struct {
	*bound
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	limiter *Limiter
	alerter Reporter
	srv     *http.Server
}

func NewHTTPProxy(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *HTTPProxyTrap {
	t := &HTTPProxyTrap{
		bound:   newBound(),
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}

	t.srv = &http.Server{
		Handler:      recoverHandler(logger, m, "httpproxy", t),
		ReadTimeout:  cfg.ResolveSessionTimeout("httpproxy"),
		WriteTimeout: cfg.ResolveSessionTimeout("httpproxy"),
		ConnContext:  ConnContextWithDestPort,
	}
	return t
}

func (t *HTTPProxyTrap) Start(ctx context.Context) error {
	addrs := t.cfg.TrapAddrs("httpproxy")
	ln, err := ListenMultiTCP(ctx, addrs, t.cfg.ProxyTrustFor("httpproxy"), t.logger, t.metrics, "httpproxy")
	if err != nil {
		return fmt.Errorf("httpproxy listen: %w", err)
	}
	t.set(ln.Addr())
	t.logger.Info("listening", "addrs", addrs)

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
	return nil
}

func (t *HTTPProxyTrap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, port := ParseAddr(r.RemoteAddr)
	destPort := DestPortFromContext(r.Context())
	sess := NewSession("httpproxy", alert.TransportTCP, host, port, destPort, t.logger)
	sess.UseSensor(t.alerter)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, t.metrics, "httpproxy", alert.TransportTCP, destPort, host, "rate_limit")
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
		cmd := "CONNECT " + sanitizeProxyTarget(r.Host)
		sess.LogCommand(cmd)
		sess.Alert(r.Context(), map[string]string{"command": cmd})
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	if r.URL.Host != "" {
		// Userinfo, query and fragment may carry secrets: keep scheme, host and path.
		target := *r.URL
		target.User = nil
		target.RawQuery = ""
		target.ForceQuery = false
		target.Fragment = ""
		target.RawFragment = ""
		cmd := r.Method + " " + target.String()
		sess.LogCommand(cmd)
		sess.Alert(r.Context(), map[string]string{"command": cmd})
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
	sess.Alert(r.Context(), map[string]string{"username": creds[0], "password": creds[1]})
}

// sanitizeProxyTarget reduces a CONNECT target to host:port (or host plus path):
// userinfo, query and fragment may carry secrets and are dropped.
func sanitizeProxyTarget(target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if i := strings.LastIndex(target, "@"); i >= 0 {
		target = target[i+1:]
	}
	return target
}
