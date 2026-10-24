package trap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// stubRequest is the common view of one request to an HTTP API stub (docker and
// kubernetes). Every value is bounded and sanitized; the body is read up to
// maxHTTPBody bytes.
type stubRequest struct {
	sess      *Session
	method    string
	path      string
	meta      map[string]string
	attrs     []slog.Attr
	body      []byte
	bodyLen   int
	truncated bool
	jndi      bool
}

// newStubRequest prepares r for a stub handler. It answers 503 and returns false
// when the connection has no session.
func newStubRequest(w http.ResponseWriter, r *http.Request) (*stubRequest, bool) {
	sess := connSession(r)
	if sess == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	req := &stubRequest{
		sess:   sess,
		method: sanitizeHTTPValue(r.Method),
		path:   sanitizeHTTPValue(r.URL.Path),
	}
	req.meta = map[string]string{
		"path":       req.path,
		"method":     req.method,
		"user_agent": sanitizeHTTPValue(r.UserAgent()),
	}
	req.attrs = []slog.Attr{
		slog.String("method", req.method),
		slog.String("path", req.path),
		slog.String("host", sanitizeHTTPValue(r.Host)),
		slog.String("user_agent", req.meta["user_agent"]),
		slog.Group("headers", httpHeaderAttrs(r)...),
	}
	// Headers are attacker-controlled: log them, never use them as alert identity.
	if claimed := claimedClientIP(r); claimed != "" {
		req.attrs = append(req.attrs, slog.String("claimed_client_ip", claimed))
	}
	req.jndi = httpHasJNDI(r)
	if r.Body != nil && r.Body != http.NoBody {
		req.body, req.bodyLen, req.truncated, _ = readHTTPBody(w, r)
	}
	return req, true
}

// command logs a command and marks the session for an alert.
func (q *stubRequest) command(cmd string) {
	cmd = sanitizeHTTPValue(cmd)
	q.meta["command"] = cmd
	q.sess.LogCommand(cmd, q.attrs...)
}

// stubTokenHashLen is the number of hex characters kept from a token hash.
const stubTokenHashLen = 8

// bearerTokenHash returns a short SHA-256 prefix of the bearer token of the
// request, or "" when there is none. The token itself is never kept.
func bearerTokenHash(r *http.Request) string {
	scheme, rest, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	tok := strings.TrimSpace(rest)
	if tok == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])[:stubTokenHashLen]
}

func writeStubJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// writeStubMessage writes {"message": msg}; msg goes through the JSON encoder.
func writeStubMessage(w http.ResponseWriter, code int, msg string) {
	b, _ := json.Marshal(map[string]string{"message": msg})
	writeStubJSON(w, code, string(b))
}

// joinStrings joins up to maxItems strings, stopping once the result reaches
// maxBytes, so the work is bounded whatever the input size.
func joinStrings(items []string, maxItems, maxBytes int) string {
	var b strings.Builder
	for i, s := range items {
		if i >= maxItems || b.Len() >= maxBytes {
			break
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s)
	}
	return b.String()
}
