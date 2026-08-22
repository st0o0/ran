package trap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type ElasticsearchTrap struct {
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	limiter *Limiter
	alerter alert.Alerter
	srv     *http.Server
	wg      sync.WaitGroup
}

func NewElasticsearch(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *ElasticsearchTrap {
	t := &ElasticsearchTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", t.handleRoot)
	mux.HandleFunc("GET /_cluster/health", t.handleClusterHealth)
	mux.HandleFunc("GET /_search", t.handleCatchAll)
	mux.HandleFunc("POST /_search", t.handleCatchAll)
	mux.HandleFunc("PUT /", t.handleCatchAll)
	mux.HandleFunc("POST /", t.handleCatchAll)
	mux.HandleFunc("DELETE /", t.handleCatchAll)

	t.srv = &http.Server{
		Handler:      mux,
		ReadTimeout:  cfg.SessionTimeout,
		WriteTimeout: cfg.SessionTimeout,
		ConnContext:  ConnContextWithDestPort,
	}
	return t
}

func (t *ElasticsearchTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("elasticsearch"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("elasticsearch listen: %w", err)
	}
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("elasticsearch"))

	go func() {
		<-ctx.Done()
		t.srv.Close()
	}()

	if err := t.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (t *ElasticsearchTrap) Stop(ctx context.Context) error {
	t.srv.Close()
	t.wg.Wait()
	return nil
}

func (t *ElasticsearchTrap) setHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-elastic-product", "Elasticsearch")
}

func (t *ElasticsearchTrap) withSession(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	host, port := ParseAddr(r.RemoteAddr)
	destPort := DestPortFromContext(r.Context())
	sess := NewSession("elasticsearch", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "elasticsearch", "tcp", destPort, host, "rate_limit")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return nil, false
	}

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	return sess, true
}

func (t *ElasticsearchTrap) releaseSession(sess *Session, host string) {
	sess.RecordEnd(t.metrics)
	sess.LogDisconnect()
	t.limiter.Release(host)
}

func (t *ElasticsearchTrap) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		t.handleCatchAll(w, r)
		return
	}

	sess, ok := t.withSession(w, r)
	if !ok {
		return
	}
	host, _ := ParseAddr(r.RemoteAddr)
	defer t.releaseSession(sess, host)

	sess.LogCommand("GET /")
	t.alerter.Alert(r.Context(), host, "elasticsearch", map[string]string{"command": "GET /"})

	t.setHeaders(w)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"name":"ran","cluster_name":"elasticsearch","cluster_uuid":"_na_","version":{"number":"8.12.0","build_flavor":"default"},"tagline":"You Know, for Search"}`)
}

func (t *ElasticsearchTrap) handleClusterHealth(w http.ResponseWriter, r *http.Request) {
	sess, ok := t.withSession(w, r)
	if !ok {
		return
	}
	host, _ := ParseAddr(r.RemoteAddr)
	defer t.releaseSession(sess, host)

	sess.LogCommand("GET /_cluster/health")
	t.alerter.Alert(r.Context(), host, "elasticsearch", map[string]string{"command": "GET /_cluster/health"})

	t.setHeaders(w)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"cluster_name":"elasticsearch","status":"green","number_of_nodes":1}`)
}

func (t *ElasticsearchTrap) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	sess, ok := t.withSession(w, r)
	if !ok {
		return
	}
	host, _ := ParseAddr(r.RemoteAddr)
	defer t.releaseSession(sess, host)

	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	cmd := r.Method + " " + r.URL.Path
	if len(body) > 0 {
		cmd += " " + string(body)
	}

	sess.LogCommand(cmd)
	t.alerter.Alert(r.Context(), host, "elasticsearch", map[string]string{"command": cmd})

	t.setHeaders(w)
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, `{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication"}],"status":401}}`)
}
