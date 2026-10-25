package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Limits of the operator fixture table (RAN_HTTP_FIXTURES).
const (
	MaxHTTPFixtures       = 64
	MaxHTTPFixtureBody    = 8 << 10
	MaxHTTPFixtureFile    = 1 << 20
	MaxHTTPFixturePath    = 256
	MaxHTTPFixtureHeaders = 16
	MaxHTTPFixtureHeader  = 256
)

// HTTPFixture is one static response of the http and https traps. Headers are keyed
// by canonical header name. Status is always set after validation.
type HTTPFixture struct {
	Path    string
	Status  int
	Headers map[string]string
	Body    string
}

// HTTPFixtureHeaders is the allow-list of response headers a fixture may set.
// Content-Length, Set-Cookie, Location, Transfer-Encoding and Content-Encoding are
// deliberately absent.
var HTTPFixtureHeaders = map[string]bool{
	"Content-Type": true, "Cache-Control": true, "Content-Language": true, "ETag": true,
	"Expires": true, "Last-Modified": true, "Server": true, "X-Powered-By": true,
	"X-Content-Type-Options": true, "X-Frame-Options": true, "X-Robots-Tag": true,
	"Link": true, "Allow": true, "WWW-Authenticate": true,
}

// HTTPFixtureStatuses is the set of status codes a fixture may use.
var HTTPFixtureStatuses = map[int]bool{
	200: true, 204: true, 400: true, 401: true, 403: true, 404: true, 500: true, 503: true,
}

type rawHTTPFixtures struct {
	Fixtures []rawHTTPFixture `json:"fixtures"`
}

type rawHTTPFixture struct {
	Path    string            `json:"path"`
	Status  *int              `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// LoadHTTPFixtures reads the fixture file at path (at most MaxHTTPFixtureFile
// bytes) and validates it. name is the variable name used in error messages.
func LoadHTTPFixtures(name, path string) ([]HTTPFixture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read fixture file: %w; check the path and permissions", name, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read fixture file: %w", name, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %s is not a regular file; point it at a JSON file", name, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxHTTPFixtureFile+1))
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read fixture file: %w", name, err)
	}
	if len(data) > MaxHTTPFixtureFile {
		return nil, fmt.Errorf("%s: fixture file is larger than %d bytes; reduce it", name, MaxHTTPFixtureFile)
	}
	return ParseHTTPFixtures(name, data)
}

// ParseHTTPFixtures validates the JSON document
// {"fixtures":[{"path":"/x","status":200,"headers":{...},"body":"..."}]}.
// Unknown fields, duplicate paths, bad headers and oversized values are errors that
// name the offending entry (1-based index and path).
func ParseHTTPFixtures(name string, data []byte) ([]HTTPFixture, error) {
	if len(data) > MaxHTTPFixtureFile {
		return nil, fmt.Errorf("%s: fixture file is larger than %d bytes; reduce it", name, MaxHTTPFixtureFile)
	}
	if err := checkDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw rawHTTPFixtures
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %v; expected {\"fixtures\":[{\"path\":\"/x\",\"status\":200,\"body\":\"...\"}]}", name, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: invalid JSON: unexpected data after the top-level object", name)
	}
	if len(raw.Fixtures) == 0 {
		return nil, fmt.Errorf("%s must define at least one entry in \"fixtures\"", name)
	}
	if len(raw.Fixtures) > MaxHTTPFixtures {
		return nil, fmt.Errorf("%s has %d entries, the limit is %d; remove some", name, len(raw.Fixtures), MaxHTTPFixtures)
	}
	out := make([]HTTPFixture, 0, len(raw.Fixtures))
	seen := make(map[string]int, len(raw.Fixtures))
	for i, r := range raw.Fixtures {
		label := fixtureLabel(i+1, r.Path)
		fx, err := validateHTTPFixture(r)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %v", name, label, err)
		}
		if first, dup := seen[fx.Path]; dup {
			return nil, fmt.Errorf("%s %s: path is already defined by entry %d; paths must be unique", name, label, first)
		}
		seen[fx.Path] = i + 1
		out = append(out, fx)
	}
	return out, nil
}

// scanFrame is one open JSON object or array of checkDuplicateKeys.
type scanFrame struct {
	obj       bool
	expectKey bool
	curKey    string
	keys      map[string]struct{}
	kind      string // top, fixtures, entry, headers or other
	n         int    // array: values seen so far
	entry     int    // 1-based fixture entry, 0 outside entries
}

// checkDuplicateKeys reports a repeated key of identical spelling in the top-level
// object, in a fixture entry or in a headers map. encoding/json silently keeps the
// last value, so it is detected with a token walk. Syntax errors are left to the
// real decoder, which reports them.
func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*scanFrame
	valueDone := func() {
		if len(stack) == 0 {
			return
		}
		f := stack[len(stack)-1]
		if f.obj {
			f.expectKey = true
		} else {
			f.n++
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		var top *scanFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.obj && top.expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					return nil
				}
				valueDone()
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return nil
			}
			if _, dup := top.keys[key]; dup {
				q := strconv.Quote(truncate(key, 64))
				switch top.kind {
				case "top":
					return fmt.Errorf("duplicate key %s in the top-level object", q)
				case "headers":
					return fmt.Errorf("entry %d: duplicate header %s", top.entry, q)
				case "entry":
					return fmt.Errorf("entry %d: duplicate key %s", top.entry, q)
				}
				return fmt.Errorf("duplicate key %s", q)
			}
			top.keys[key] = struct{}{}
			top.curKey = key
			top.expectKey = false
			continue
		}
		d, isDelim := tok.(json.Delim)
		if !isDelim {
			if top == nil {
				return nil
			}
			valueDone()
			continue
		}
		switch d {
		case '{', '[':
			f := &scanFrame{obj: d == '{', kind: "other"}
			if f.obj {
				f.keys = make(map[string]struct{})
				f.expectKey = true
			}
			switch {
			case top == nil && f.obj:
				f.kind = "top"
			case top == nil:
				return nil
			case top.kind == "top" && top.curKey == "fixtures" && !f.obj:
				f.kind = "fixtures"
			case top.kind == "fixtures" && f.obj:
				f.kind, f.entry = "entry", top.n+1
			case top.kind == "entry" && top.curKey == "headers" && f.obj:
				f.kind, f.entry = "headers", top.entry
			}
			stack = append(stack, f)
		default:
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return nil
			}
			valueDone()
		}
	}
}

func fixtureLabel(n int, path string) string {
	if len(path) > 64 {
		path = path[:64] + "..."
	}
	return fmt.Sprintf("entry %d (path %s)", n, strconv.Quote(path))
}

func validateHTTPFixture(r rawHTTPFixture) (HTTPFixture, error) {
	if err := validateFixturePath(r.Path); err != nil {
		return HTTPFixture{}, err
	}
	status := http.StatusOK
	if r.Status != nil {
		status = *r.Status
	}
	if !HTTPFixtureStatuses[status] {
		return HTTPFixture{}, fmt.Errorf("status %d is not allowed; use one of 200, 204, 400, 401, 403, 404, 500, 503", status)
	}
	if len(r.Body) > MaxHTTPFixtureBody {
		return HTTPFixture{}, fmt.Errorf("body is %d bytes, the limit is %d", len(r.Body), MaxHTTPFixtureBody)
	}
	if status == http.StatusNoContent && r.Body != "" {
		return HTTPFixture{}, errors.New("status 204 must have an empty body")
	}
	if len(r.Headers) > MaxHTTPFixtureHeaders {
		return HTTPFixture{}, fmt.Errorf("%d headers, the limit is %d", len(r.Headers), MaxHTTPFixtureHeaders)
	}
	names := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	hdrs := make(map[string]string, len(r.Headers))
	for _, k := range names {
		v := r.Headers[k]
		canon := http.CanonicalHeaderKey(k)
		if !HTTPFixtureHeaders[canon] {
			return HTTPFixture{}, fmt.Errorf("header %s is not allowed; allowed: %s", strconv.Quote(truncate(k, 64)), allowedHeaderList())
		}
		if _, dup := hdrs[canon]; dup {
			return HTTPFixture{}, fmt.Errorf("header %s is set twice", canon)
		}
		if len(v) > MaxHTTPFixtureHeader {
			return HTTPFixture{}, fmt.Errorf("header %s value is %d bytes, the limit is %d", canon, len(v), MaxHTTPFixtureHeader)
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7e {
				return HTTPFixture{}, fmt.Errorf("header %s value must be printable ASCII", canon)
			}
		}
		hdrs[canon] = v
	}
	return HTTPFixture{Path: r.Path, Status: status, Headers: hdrs, Body: r.Body}, nil
}

func validateFixturePath(p string) error {
	switch {
	case p == "" || p[0] != '/':
		return errors.New("path must start with /")
	case len(p) > MaxHTTPFixturePath:
		return fmt.Errorf("path is %d bytes, the limit is %d", len(p), MaxHTTPFixturePath)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c <= 0x20 || c >= 0x7f {
			return errors.New("path must be printable ASCII without spaces or control characters")
		}
		if c == '?' || c == '#' {
			return errors.New("path must not contain ? or # (the query is never matched)")
		}
		if c == '%' {
			return errors.New("path must not contain % (requests are matched on the decoded path, so an encoded path never matches; write the decoded character)")
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func allowedHeaderList() string {
	names := make([]string, 0, len(HTTPFixtureHeaders))
	for k := range HTTPFixtureHeaders {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
