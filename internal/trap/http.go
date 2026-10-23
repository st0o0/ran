package trap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// maxHTTPBody caps request bodies and headers.
const maxHTTPBody = 16 << 10

type HTTPTrap struct {
	*bound
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	limiter *Limiter
	alerter Reporter
	srv     *http.Server
	// conns maps each accepted connection to its per-connection state. The key is
	// the net.Conn itself, never RemoteAddr: under PROXY protocol RemoteAddr is
	// client controlled and can collide between connections.
	conns sync.Map
}

func NewHTTP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *HTTPTrap {
	t := &HTTPTrap{
		bound:   newBound(),
		cfg:     cfg,
		logger:  logger,
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
		Handler:      recoverHandler(logger, m, "http", mux),
		ReadTimeout:  cfg.ResolveSessionTimeout("http"),
		WriteTimeout: cfg.ResolveSessionTimeout("http"),
		ConnState:    t.connState,
		ConnContext:  t.connContext,

		MaxHeaderBytes: maxHTTPBody,
	}
	return t
}

// httpConn is the state of one accepted connection. sess is set in connState
// (StateNew) before the handler can run and cleared on close.
type httpConn struct {
	sess *Session
}

type httpConnKey struct{}

// connContext runs before connState(StateNew) for the same connection. It
// creates the per-connection state and hands it to the handlers via the
// request context.
func (t *HTTPTrap) connContext(ctx context.Context, conn net.Conn) context.Context {
	hc := &httpConn{}
	t.conns.Store(conn, hc)
	return context.WithValue(ConnContextWithDestPort(ctx, conn), httpConnKey{}, hc)
}

func (t *HTTPTrap) connState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		v, ok := t.conns.Load(conn)
		if !ok {
			conn.Close()
			return
		}
		hc := v.(*httpConn)
		host, port := ParseAddr(conn.RemoteAddr().String())
		_, destPort := ParseAddr(conn.LocalAddr().String())
		if !t.limiter.Acquire(host) {
			LogRejected(t.logger, t.metrics, "http", alert.TransportTCP, destPort, host, "rate_limit")
			conn.Close()
			return
		}
		sess := NewSession("http", alert.TransportTCP, host, port, destPort, t.logger)
		sess.Sensor = t.alerter
		hc.sess = sess
		sess.LogConnect()
		sess.RecordStart(t.metrics)
	case http.StateClosed, http.StateHijacked:
		v, ok := t.conns.LoadAndDelete(conn)
		if !ok {
			return
		}
		if sess := v.(*httpConn).sess; sess != nil {
			sess.LogDisconnect()
			sess.RecordEnd(t.metrics)
			t.limiter.Release(sess.SourceIP)
		}
	}
}

func (t *HTTPTrap) Start(ctx context.Context) error {
	addrs := t.cfg.TrapAddrs("http")
	ln, err := ListenMultiTCP(ctx, addrs, t.cfg.ProxyProtocol, t.logger, t.metrics, "http")
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
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

func (t *HTTPTrap) Stop(ctx context.Context) error {
	t.srv.Close()
	return nil
}

func (t *HTTPTrap) handleLogin(style string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hc, _ := r.Context().Value(httpConnKey{}).(*httpConn)
		if hc == nil || hc.sess == nil {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		sess := hc.sess

		w.Header().Set("Server", "Apache/2.4.62")
		w.Header().Set("X-Powered-By", "PHP/8.3.6")

		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxHTTPBody)
			_ = r.ParseForm()
			username := firstOf(r.PostForm, "username", "user", "log")
			password := firstOf(r.PostForm, "password", "pass", "pwd")
			attrs := []slog.Attr{
				slog.String("username", username),
				slog.String("password", password),
				slog.String("path", r.URL.Path),
			}
			// Headers are attacker-controlled: log them, never use them as alert identity.
			if claimed := claimedClientIP(r); claimed != "" {
				attrs = append(attrs, slog.String("claimed_client_ip", claimed))
			}
			sess.LogAuthAttempt(attrs...)
			sess.RecordCredentials(t.metrics)
			sess.Alert(r.Context(), map[string]string{"username": username, "password": password, "path": r.URL.Path})
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

// claimedClientIP returns the forwarding header IP if it is syntactically valid, else "".
func claimedClientIP(r *http.Request) string {
	raw := ""
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		raw = strings.TrimSpace(ip)
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		raw = strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
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
