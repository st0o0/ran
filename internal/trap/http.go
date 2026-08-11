package trap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type HTTPTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	srv      *http.Server
	sessions sync.Map
}

func NewHTTP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) *HTTPTrap {
	t := &HTTPTrap{
		cfg:     cfg,
		logger:  logger.With("trap", "http"),
		metrics: m,
		limiter: limiter,
		alerter: alerter,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/wp-login.php", t.handleLogin("wordpress"))
	mux.HandleFunc("/admin", t.handleLogin("admin"))
	mux.HandleFunc("/", t.handleLogin("generic"))

	t.srv = &http.Server{
		Addr:         cfg.TrapAddr("http"),
		Handler:      mux,
		ReadTimeout:  cfg.SessionTimeout,
		WriteTimeout: cfg.SessionTimeout,
		ConnState:    t.connState,
	}
	return t
}

func (t *HTTPTrap) connState(conn net.Conn, state http.ConnState) {
	addr := conn.RemoteAddr().String()
	switch state {
	case http.StateNew:
		host, port := ParseAddr(addr)
		if !t.limiter.Acquire(host) {
			t.logger.Warn("connection rejected", "source_ip", host, "reason", "limit_exceeded")
			conn.Close()
			return
		}
		sess := NewSession("http", host, port)
		t.sessions.Store(addr, sess)
		sess.LogConnect(t.logger)
		sess.RecordStart(t.metrics)
	case http.StateClosed, http.StateHijacked:
		if v, ok := t.sessions.LoadAndDelete(addr); ok {
			sess := v.(*Session)
			sess.LogDisconnect(t.logger)
			sess.RecordEnd(t.metrics)
			t.limiter.Release(sess.SourceIP)
		}
	}
}

func (t *HTTPTrap) Start(ctx context.Context) error {
	ln, err := ListenTCP(ctx, t.cfg.TrapAddr("http"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	t.logger.Info("listening", "addr", t.cfg.TrapAddr("http"))

	go func() {
		<-ctx.Done()
		t.srv.Close()
	}()

	if err := t.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (t *HTTPTrap) Stop(ctx context.Context) error {
	t.srv.Close()
	return nil
}

func (t *HTTPTrap) handleLogin(style string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := t.sessions.Load(r.RemoteAddr)
		if !ok {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		sess := v.(*Session)

		w.Header().Set("Server", "Apache/2.4.62")
		w.Header().Set("X-Powered-By", "PHP/8.3.6")

		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			username := firstOf(r.PostForm, "username", "user", "log")
			password := firstOf(r.PostForm, "password", "pass", "pwd")
			attrs := []slog.Attr{
				slog.String("username", username),
				slog.String("password", password),
				slog.String("path", r.URL.Path),
			}
			if clientIP := clientIPFromHeaders(r); clientIP != "" {
				attrs = append(attrs, slog.String("client_ip", clientIP))
			}
			sess.LogAuthAttempt(t.logger, attrs...)
			sess.RecordCredentials(t.metrics)
			alertIP := sess.SourceIP
			if ip := clientIPFromHeaders(r); ip != "" {
				alertIP = ip
			}
			t.alerter.Alert(r.Context(), alertIP, "http")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, loginErrorPage(style))
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, loginPage(style))
	}
}


func clientIPFromHeaders(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return ""
}

func firstOf(form map[string][]string, keys ...string) string {
	for _, k := range keys {
		if vals, ok := form[k]; ok && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func loginPage(style string) string {
	switch style {
	case "wordpress":
		return wpLoginPage
	case "admin":
		return adminLoginPage
	default:
		return adminLoginPage
	}
}

func loginErrorPage(style string) string {
	switch style {
	case "wordpress":
		return wpLoginErrorPage
	default:
		return adminLoginErrorPage
	}
}

const wpLoginPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title>
<style>body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.login{width:320px;margin:100px auto;padding:26px 24px;background:#fff;border:1px solid #c3c4c7;border-radius:4px}
h1{text-align:center;margin-bottom:24px}
label{display:block;margin-bottom:4px;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:8px;margin-bottom:16px;box-sizing:border-box;border:1px solid #8c8f94;border-radius:4px}
input[type=submit]{width:100%;padding:8px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}
</style></head>
<body><div class="login"><h1>WordPress</h1>
<form method="post"><label for="log">Username or Email</label>
<input type="text" name="log" id="log">
<label for="pwd">Password</label>
<input type="password" name="pwd" id="pwd">
<input type="submit" value="Log In"></form></div></body></html>`

const wpLoginErrorPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title>
<style>body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.login{width:320px;margin:100px auto;padding:26px 24px;background:#fff;border:1px solid #c3c4c7;border-radius:4px}
.error{background:#fcf0f1;border:1px solid #d63638;padding:12px;margin-bottom:16px;border-radius:4px;color:#d63638;font-size:14px}
h1{text-align:center;margin-bottom:24px}
label{display:block;margin-bottom:4px;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:8px;margin-bottom:16px;box-sizing:border-box;border:1px solid #8c8f94;border-radius:4px}
input[type=submit]{width:100%;padding:8px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}
</style></head>
<body><div class="login"><h1>WordPress</h1>
<div class="error"><strong>Error:</strong> The username or password you entered is incorrect.</div>
<form method="post"><label for="log">Username or Email</label>
<input type="text" name="log" id="log">
<label for="pwd">Password</label>
<input type="password" name="pwd" id="pwd">
<input type="submit" value="Log In"></form></div></body></html>`

const adminLoginPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Login</title>
<style>body{background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.login{width:320px;margin:100px auto;padding:26px 24px;background:#fff;border:1px solid #ddd;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
h1{text-align:center;margin-bottom:24px;font-size:20px}
label{display:block;margin-bottom:4px;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:8px;margin-bottom:16px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
input[type=submit]{width:100%;padding:8px;background:#333;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}
</style></head>
<body><div class="login"><h1>Admin Login</h1>
<form method="post"><label for="username">Username</label>
<input type="text" name="username" id="username">
<label for="password">Password</label>
<input type="password" name="password" id="password">
<input type="submit" value="Sign In"></form></div></body></html>`

const adminLoginErrorPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Login</title>
<style>body{background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.login{width:320px;margin:100px auto;padding:26px 24px;background:#fff;border:1px solid #ddd;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.error{background:#fef2f2;border:1px solid #ef4444;padding:12px;margin-bottom:16px;border-radius:4px;color:#dc2626;font-size:14px}
h1{text-align:center;margin-bottom:24px;font-size:20px}
label{display:block;margin-bottom:4px;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:8px;margin-bottom:16px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
input[type=submit]{width:100%;padding:8px;background:#333;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}
</style></head>
<body><div class="login"><h1>Admin Login</h1>
<div class="error">Invalid credentials. Please try again.</div>
<form method="post"><label for="username">Username</label>
<input type="text" name="username" id="username">
<label for="password">Password</label>
<input type="password" name="password" id="password">
<input type="submit" value="Sign In"></form></div></body></html>`
