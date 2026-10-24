package trap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// Limits for what is taken from an MCP request.
const (
	// maxMCPBatch is the largest accepted JSON-RPC batch; a bigger one is rejected
	// as a whole with -32600.
	maxMCPBatch = 16
	// maxMCPName bounds method names, tool names, client names and string ids.
	maxMCPName = 64
	// maxMCPArgKeys is the number of argument keys kept in the summary.
	maxMCPArgKeys = 8
	// maxMCPArgValue is the number of bytes kept from each argument value.
	maxMCPArgValue = 128
	// maxMCPArgsSummary bounds the whole argument summary: per key the key, a
	// separator, the value and a space.
	maxMCPArgsSummary = maxMCPArgKeys * (maxMCPName + 1 + maxMCPArgValue + 1)
	// maxMCPIDDigits bounds a numeric id that is echoed.
	maxMCPIDDigits = 15
)

// JSON-RPC 2.0 error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
)

// mcpProtocolVersions is the allow-list for the protocolVersion echo; the first
// entry is the answer for anything else.
var mcpProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// MCPTrap is a static decoy of a Model Context Protocol server (JSON-RPC 2.0 over
// HTTP). It reuses the HTTP trap for listening, per-connection sessions, limits and
// shutdown, and only swaps the request handler. No tool is ever executed.
type MCPTrap struct {
	*HTTPTrap
}

func NewMCP(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *MCPTrap {
	t := &MCPTrap{HTTPTrap: newHTTPTrap("mcp", cfg, logger, m, limiter, alerter)}
	t.setHandler(t.handle)
	return t
}

// rpcError is a JSON-RPC error object. Messages are fixed strings.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcCall is one parsed JSON-RPC message. Everything in it is bounded and
// sanitized: id is "null" or a validated number or short string literal, method is
// cut to maxMCPName bytes.
type rpcCall struct {
	id        json.RawMessage
	hasID     bool
	method    string
	params    json.RawMessage
	invalid   bool
	rawMethod string
}

// rpcParsed is the result of parseJSONRPC. err is set when the whole body is
// rejected (parse error, empty or oversized batch).
type rpcParsed struct {
	calls []rpcCall
	batch bool
	err   *rpcError
}

type rpcEnvelope struct {
	JSONRPC any             `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  any             `json:"method"`
	Params  json.RawMessage `json:"params"`
}

var nullID = json.RawMessage("null")

// parseJSONRPC parses a request body. The body must already be limited (it is at
// most maxHTTPBody bytes); json.Valid and the decoder are iterative and refuse
// nesting deeper than 10000, so a hostile body cannot exhaust the stack.
func parseJSONRPC(body []byte) rpcParsed {
	body = bytes.TrimSpace(body)
	if !json.Valid(body) {
		return rpcParsed{err: &rpcError{rpcParseError, "Parse error"}}
	}
	if len(body) > 0 && body[0] == '[' {
		var raws []json.RawMessage
		if json.Unmarshal(body, &raws) != nil {
			return rpcParsed{err: &rpcError{rpcParseError, "Parse error"}}
		}
		if len(raws) == 0 || len(raws) > maxMCPBatch {
			return rpcParsed{batch: true, err: &rpcError{rpcInvalidRequest, "Invalid Request"}}
		}
		calls := make([]rpcCall, 0, len(raws))
		for _, raw := range raws {
			calls = append(calls, parseRPCCall(raw))
		}
		return rpcParsed{calls: calls, batch: true}
	}
	return rpcParsed{calls: []rpcCall{parseRPCCall(body)}}
}

func parseRPCCall(raw json.RawMessage) rpcCall {
	c := rpcCall{id: nullID}
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		c.invalid = true
		return c
	}
	if env.ID != nil {
		c.hasID = true
		c.id = sanitizeRPCID(env.ID)
	}
	method, isStr := env.Method.(string)
	if v, _ := env.JSONRPC.(string); v != "2.0" || !isStr || method == "" {
		c.invalid = true
		return c
	}
	c.rawMethod = method
	c.method = sanitizeMCPText(method, maxMCPName)
	c.params = env.Params
	return c
}

// sanitizeRPCID returns raw if it is a small integer or a short string of safe
// characters, else null. The returned value is therefore safe to echo.
func sanitizeRPCID(raw json.RawMessage) json.RawMessage {
	s := string(raw)
	if len(s) == 0 {
		return nullID
	}
	if s[0] == '"' {
		var str string
		if json.Unmarshal(raw, &str) != nil || len(str) == 0 || len(str) > maxMCPName {
			return nullID
		}
		for i := 0; i < len(str); i++ {
			c := str[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':'
			if !ok {
				return nullID
			}
		}
		// Echo the validated string, not the raw JSON: escapes in the raw text
		// would make it longer than the bound.
		out, err := json.Marshal(str)
		if err != nil {
			return nullID
		}
		return out
	}
	digits := strings.TrimPrefix(s, "-")
	if len(digits) == 0 || len(digits) > maxMCPIDDigits {
		return nullID
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return nullID
		}
	}
	return raw
}

// sanitizeMCPText cuts s to n bytes at a rune boundary, then replaces control and
// format characters. The result is never longer than n bytes.
func sanitizeMCPText(s string, n int) string {
	return sanitizeHTTPValue(truncateRunes(s, n))
}

// secretArgKey reports whether the value of an argument key is not recorded (see
// secretNameParts). String values of other keys are scrubbed when logged.
func secretArgKey(k string) bool { return secretName(k) }

// summarizeMCPArgs returns "key=value" pairs for at most maxMCPArgKeys keys of the
// arguments object (sorted, so the result is deterministic). String values are cut
// to maxMCPArgValue bytes; objects and arrays are not descended into. The result
// is at most maxMCPArgsSummary bytes and holds no control or format characters.
func summarizeMCPArgs(args json.RawMessage) string {
	if len(args) == 0 || string(args) == "null" {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(args, &m) != nil {
		return "(non-object arguments)"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxMCPArgKeys {
		keys = keys[:maxMCPArgKeys]
	}
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(sanitizeMCPText(k, maxMCPName))
		b.WriteByte('=')
		if secretArgKey(k) {
			b.WriteString("***")
			continue
		}
		b.WriteString(summarizeMCPValue(m[k]))
	}
	return b.String()
}

func summarizeMCPValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return ""
		}
		return sanitizeMCPText(s, maxMCPArgValue)
	case '{':
		return "<object>"
	case '[':
		return "<array>"
	default:
		return sanitizeMCPText(string(raw), maxMCPArgValue)
	}
}

type mcpCallParams struct {
	Name      any             `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// mcpToolCall extracts the tool name and the argument summary of a tools/call.
// ok is false when the params are not an object with a string name.
func mcpToolCall(params json.RawMessage) (tool, args string, ok bool) {
	var p mcpCallParams
	if len(params) == 0 || json.Unmarshal(params, &p) != nil {
		return "", "", false
	}
	name, isStr := p.Name.(string)
	if !isStr {
		return "", summarizeMCPArgs(p.Arguments), false
	}
	return sanitizeMCPText(name, maxMCPName), summarizeMCPArgs(p.Arguments), true
}

// mcpCredentialHash returns a short SHA-256 prefix of the credential header of the
// request (Authorization, else X-API-Key) and the header name, or "" when there is
// none. The value itself is never kept.
func mcpCredentialHash(r *http.Request) (hash, header string) {
	for _, h := range []string{"Authorization", "X-Api-Key"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			sum := sha256.Sum256([]byte(v))
			return hex.EncodeToString(sum[:])[:stubTokenHashLen], strings.ToLower(h)
		}
	}
	return "", ""
}

func mcpClientInfo(params json.RawMessage) (name, version string) {
	var p struct {
		ClientInfo struct {
			Name    any `json:"name"`
			Version any `json:"version"`
		} `json:"clientInfo"`
	}
	if json.Unmarshal(params, &p) != nil {
		return "", ""
	}
	n, _ := p.ClientInfo.Name.(string)
	v, _ := p.ClientInfo.Version.(string)
	return sanitizeMCPText(n, maxMCPName), sanitizeMCPText(v, maxMCPName)
}

// mcpProtocolVersion echoes the requested protocol version only when it is on the
// allow-list; any other client string is never reflected.
func mcpProtocolVersion(params json.RawMessage) string {
	var p struct {
		ProtocolVersion any `json:"protocolVersion"`
	}
	if json.Unmarshal(params, &p) == nil {
		if v, ok := p.ProtocolVersion.(string); ok {
			for _, allowed := range mcpProtocolVersions {
				if v == allowed {
					return allowed
				}
			}
		}
	}
	return mcpProtocolVersions[0]
}

var mcpTools = []map[string]any{
	mcpTool("read_file", "Read the contents of a file from the local filesystem.",
		map[string]any{"path": map[string]any{"type": "string", "description": "Absolute path of the file"}}, "path"),
	mcpTool("list_directory", "List the files and directories in a path.",
		map[string]any{"path": map[string]any{"type": "string", "description": "Directory path"}}, "path"),
	mcpTool("run_command", "Run a shell command on the host and return its output.",
		map[string]any{
			"command": map[string]any{"type": "string", "description": "Shell command line"},
			"cwd":     map[string]any{"type": "string", "description": "Working directory"},
		}, "command"),
	mcpTool("get_secrets", "Return a stored secret such as an API key or a credential.",
		map[string]any{"name": map[string]any{"type": "string", "description": "Name of the secret"}}, "name"),
}

func mcpTool(name, desc string, props map[string]any, required ...string) map[string]any {
	return map[string]any{
		"name":        name,
		"description": desc,
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": required},
	}
}

var (
	mcpCallError = map[string]any{
		"isError": true,
		"content": []map[string]any{{"type": "text", "text": "Error: permission denied. The operation is not allowed for this session."}},
	}
	mcpInitResult = func(version string) map[string]any {
		return map[string]any{
			"protocolVersion": version,
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"listChanged": false, "subscribe": false},
				"prompts":   map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{"name": "filesystem-server", "version": "0.6.2"},
		}
	}
)

// mcpRequest is the state of one HTTP request while its messages are answered.
type mcpRequest struct {
	req     *stubRequest
	alerted bool
	// commandSet is true once the alert meta carries a tool call.
	commandSet bool
}

// answer handles one message and returns the response, or nil for a notification.
func (q *mcpRequest) answer(c rpcCall) *rpcResponse {
	resp := &rpcResponse{JSONRPC: "2.0", ID: c.id}
	if c.invalid {
		q.req.sess.Log("mcp invalid request", q.req.attrs...)
		resp.Error = &rpcError{rpcInvalidRequest, "Invalid Request"}
		return resp
	}
	sess := q.req.sess
	attrs := append(append([]slog.Attr(nil), q.req.attrs...), slog.String("mcp_method", c.method))
	var result any
	switch c.rawMethod {
	case "initialize":
		name, version := mcpClientInfo(c.params)
		if name != "" || version != "" {
			attrs = append(attrs, slog.String("client_name", name), slog.String("client_version", version))
		}
		sess.Log("mcp initialize", attrs...)
		result = mcpInitResult(mcpProtocolVersion(c.params))
	case "ping":
		sess.Log("mcp ping", attrs...)
		result = map[string]any{}
	case "notifications/initialized":
		sess.Log("mcp notification", attrs...)
		result = map[string]any{}
	case "tools/list":
		sess.Log("mcp tools/list", attrs...)
		result = map[string]any{"tools": mcpTools}
	case "resources/list":
		sess.Log("mcp resources/list", attrs...)
		result = map[string]any{"resources": []any{}}
	case "prompts/list":
		sess.Log("mcp prompts/list", attrs...)
		result = map[string]any{"prompts": []any{}}
	case "tools/call":
		q.recordToolCall(c, attrs)
		result = mcpCallError
	default:
		sess.Log("mcp unknown method", attrs...)
		if !c.hasID {
			return nil
		}
		resp.Error = &rpcError{rpcMethodNotFound, "Method not found"}
		return resp
	}
	if !c.hasID {
		return nil
	}
	resp.Result = result
	return resp
}

// recordToolCall logs a tools/call as a command. Only the first call of a request
// fills the alert meta; every call is logged and counted.
func (q *mcpRequest) recordToolCall(c rpcCall, attrs []slog.Attr) {
	tool, args, _ := mcpToolCall(c.params)
	line := "tools/call " + tool
	if args != "" {
		line += " " + args
	}
	// The meta goes to CrowdSec and is always scrubbed; the log follows
	// RAN_LOG_PASSWORDS.
	attrs = append(attrs, slog.String("tool", tool), slog.String("arguments", logScrubSecrets(args)))
	q.req.sess.LogCommand(logCommandText(line), attrs...)
	q.alerted = true
	if !q.commandSet {
		q.commandSet = true
		q.req.meta["command"] = metaCommandText(line)
		q.req.meta["tool"] = tool
	}
}

func writeMCPJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (t *MCPTrap) handle(w http.ResponseWriter, r *http.Request) {
	req, ok := newStubRequest(w, r)
	if !ok {
		return
	}
	sess := req.sess
	q := &mcpRequest{req: req}
	route := r.URL.Path

	if hash, header := mcpCredentialHash(r); hash != "" {
		// The credential is never kept: only a short hash prefix.
		sess.LogAuthAttempt(slog.String("token_hash", hash), slog.String("header", header), slog.String("path", req.path))
		sess.RecordCredentials(t.metrics)
		req.meta["token_hash"] = hash
		q.alerted = true
	}
	if matchExploitPath(route) || req.jndi {
		req.command(req.method + " " + req.path)
		q.alerted = true
	}

	finish := func() {
		if q.alerted {
			sess.Alert(r.Context(), req.meta)
		}
	}

	switch {
	case route == "/" || route == "/mcp":
		if r.Method != http.MethodPost {
			sess.Log("mcp request", req.attrs...)
			finish()
			w.Header().Set("Allow", "POST")
			writeMCPJSON(w, http.StatusMethodNotAllowed, rpcResponse{JSONRPC: "2.0", ID: nullID, Error: &rpcError{rpcInvalidRequest, "Method not allowed"}})
			return
		}
		if req.truncated {
			sess.Log("mcp request too large", req.attrs...)
			finish()
			writeMCPJSON(w, http.StatusRequestEntityTooLarge, rpcResponse{JSONRPC: "2.0", ID: nullID, Error: &rpcError{rpcInvalidRequest, "Request too large"}})
			return
		}
		if matchJNDI(string(req.body[:min(len(req.body), maxHTTPMatch)])) {
			req.command(req.method + " " + req.path)
			q.alerted = true
		}
		parsed := parseJSONRPC(req.body)
		if parsed.err != nil {
			sess.Log("mcp malformed request", req.attrs...)
			finish()
			writeMCPJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: nullID, Error: parsed.err})
			return
		}
		resps := make([]*rpcResponse, 0, len(parsed.calls))
		for _, c := range parsed.calls {
			if resp := q.answer(c); resp != nil {
				resps = append(resps, resp)
			}
		}
		finish()
		switch {
		case len(resps) == 0:
			w.WriteHeader(http.StatusAccepted)
		case parsed.batch:
			writeMCPJSON(w, http.StatusOK, resps)
		default:
			writeMCPJSON(w, http.StatusOK, resps[0])
		}
	case route == "/sse" && r.Method == http.MethodGet:
		// A closed stream: the endpoint event is sent and the response ends.
		sess.Log("mcp sse", req.attrs...)
		finish()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: endpoint\ndata: /mcp\n\n"))
	default:
		sess.Log("mcp request", req.attrs...)
		finish()
		http.NotFound(w, r)
	}
}
