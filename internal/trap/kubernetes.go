package trap

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// Limits for what is taken from a kubelet execution request.
const (
	maxKubeCmdItems = 32
	maxKubeCmdBytes = 1024
)

// KubernetesTrap is a stub of the Kubernetes API server and the kubelet API. It
// reuses the HTTP trap for listening, per-connection sessions, limits and
// shutdown, and only swaps the request handler.
type KubernetesTrap struct {
	*HTTPTrap
}

func NewKubernetes(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *KubernetesTrap {
	t := &KubernetesTrap{HTTPTrap: newHTTPTrap("kubernetes", cfg, logger, m, limiter, alerter)}
	t.setHandler(t.handle)
	return t
}

const (
	kubeVersionJSON = `{"major":"1","minor":"29","gitVersion":"v1.29.4","gitCommit":"55019c83b0fd51ef5d8d2d1d5c3ba10fb02bd8f3","gitTreeState":"clean","buildDate":"2024-04-16T15:07:19Z","goVersion":"go1.21.9","compiler":"gc","platform":"linux/amd64"}`
	kubeAPIJSON     = `{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"127.0.0.1:6443"}]}`
)

// kubeExecPrefixes are the kubelet endpoints that run commands in a container.
var kubeExecPrefixes = []string{"/run/", "/exec/", "/attach/"}

func isKubeExec(route string) bool {
	for _, p := range kubeExecPrefixes {
		if strings.HasPrefix(route, p) {
			return true
		}
	}
	return false
}

// writeKubeStatus writes a Kubernetes Status object. Every value is encoded.
func writeKubeStatus(w http.ResponseWriter, code int, reason, msg string) {
	b, _ := json.Marshal(map[string]any{
		"kind": "Status", "apiVersion": "v1", "metadata": map[string]any{},
		"status": "Failure", "message": msg, "reason": reason, "details": map[string]any{}, "code": code,
	})
	writeStubJSON(w, code, string(b))
}

func (t *KubernetesTrap) handle(w http.ResponseWriter, r *http.Request) {
	req, ok := newStubRequest(w, r)
	if !ok {
		return
	}
	sess := req.sess
	route := "/"
	if len(r.URL.Path) <= maxHTTPPath {
		route = path.Clean("/" + r.URL.Path)
	}
	readOnly := isReadOnlyMethod(r.Method)
	alerted := false

	tokenHash := bearerTokenHash(r)
	if tokenHash != "" {
		// The token is a credential: only a short hash prefix is kept.
		sess.LogAuthAttempt(slog.String("token_hash", tokenHash), slog.String("path", req.path))
		sess.RecordCredentials(t.metrics)
		req.meta["token_hash"] = tokenHash
		alerted = true
	}

	switch {
	case req.jndi:
		req.command(req.method + " " + req.path)
		alerted = true
	case isKubeExec(route):
		req.command(req.method + " " + req.path + " cmd=" + kubeCommand(r, req))
		alerted = true
	case !readOnly:
		req.command(req.method + " " + req.path)
		alerted = true
	default:
		sess.Log("kubernetes request", req.attrs...)
	}
	if req.bodyLen > 0 && !alerted {
		sess.LogPayloadSize("http_body", req.bodyLen, slog.String("path", req.path), slog.Int("bytes", req.bodyLen))
		alerted = true
	}
	if alerted {
		sess.Alert(r.Context(), req.meta)
	}

	switch {
	case isKubeExec(route):
		writeKubeAuthError(w, tokenHash != "", req.path, r.Method)
	case !readOnly:
		writeKubeAuthError(w, tokenHash != "", req.path, r.Method)
	case route == "/version":
		writeStubJSON(w, http.StatusOK, kubeVersionJSON)
	case route == "/api":
		writeStubJSON(w, http.StatusOK, kubeAPIJSON)
	case route == "/healthz", route == "/livez", route == "/readyz":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("ok"))
		}
	case route == "/pods", route == "/runningpods", strings.HasPrefix(route, "/pods/"), strings.HasPrefix(route, "/runningpods/"):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	default:
		writeKubeAuthError(w, tokenHash != "", req.path, r.Method)
	}
}

// writeKubeAuthError answers 401 when a token was presented (and is wrong) and
// 403 for the anonymous user, as an API server does.
func writeKubeAuthError(w http.ResponseWriter, hadToken bool, p, method string) {
	if hadToken {
		writeKubeStatus(w, http.StatusUnauthorized, "Unauthorized", "Unauthorized")
		return
	}
	verb := "get"
	if method != http.MethodGet && method != http.MethodHead {
		verb = "create"
	}
	writeKubeStatus(w, http.StatusForbidden, "Forbidden",
		"forbidden: User \"system:anonymous\" cannot "+verb+" path "+strconv.Quote(p))
}

// kubeCommand returns the command of a kubelet execution request, taken from the
// cmd and command parameters of the query string and of a form body. The result
// is bounded; the body was already limited to maxHTTPBody bytes.
func kubeCommand(r *http.Request, req *stubRequest) string {
	var vals []string
	vals = append(vals, r.URL.Query()["cmd"]...)
	vals = append(vals, r.URL.Query()["command"]...)
	if !req.truncated && req.bodyLen > 0 {
		vals = append(vals, formCommand(req.body)...)
	}
	return joinStrings(vals, maxKubeCmdItems, maxKubeCmdBytes)
}

// formCommand returns the cmd and command values of a urlencoded body.
func formCommand(body []byte) []string {
	q, _ := url.ParseQuery(string(body))
	return append(append([]string(nil), q["cmd"]...), q["command"]...)
}
