package trap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// Fuzz targets for the parsers that handle raw attacker bytes. All of them share
// the same contract: never panic, and keep the output bounded by the input
// (text decoded from the input may grow by a small constant factor, for example
// UTF-16 to UTF-8 or IP address formatting).

const fuzzOutputSlack = 64

// boundedText fails when decoded text is longer than the input allows.
func boundedText(t *testing.T, in []byte, outs ...string) {
	t.Helper()
	total := 0
	for _, o := range outs {
		total += len(o)
	}
	if limit := 4*len(in) + fuzzOutputSlack; total > limit {
		t.Fatalf("output of %d bytes for %d input bytes (limit %d)", total, len(in), limit)
	}
}

// boundedPayload fails when a framed reader returns more bytes than it was fed.
func boundedPayload(t *testing.T, in, payload []byte) {
	t.Helper()
	if len(payload) > len(in) {
		t.Fatalf("payload of %d bytes from %d input bytes", len(payload), len(in))
	}
}

func FuzzParseV1V2(f *testing.F) {
	f.Add([]byte("PROXY TCP4 8.8.8.8 1.1.1.1 12345 80\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add(append([]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C},
		8, 8, 8, 8, 1, 1, 1, 1, 0x30, 0x39, 0x00, 0x50))
	f.Fuzz(func(t *testing.T, data []byte) {
		if a, err := parseV1(bufio.NewReader(bytes.NewReader(data))); err == nil && a != nil {
			boundedText(t, data, a.String())
		}
		if a, err := parseV2(bufio.NewReader(bytes.NewReader(data))); err == nil && a != nil {
			boundedText(t, data, a.String())
		}
	})
}

func FuzzParseNTLMSSPAuth(f *testing.F) {
	f.Add([]byte("NTLMSSP\x00\x03\x00\x00\x00"))
	f.Add(make([]byte, 80))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, u, w := parseNTLMSSPAuth(data)
		boundedText(t, data, d, u, w)
	})
}

func FuzzReadPgStartup(f *testing.F) {
	f.Add([]byte{0, 0, 0, 20, 0, 3, 0, 0, 'u', 's', 'e', 'r', 0, 'b', 'o', 'b', 0, 0})
	f.Add([]byte{0, 0, 0, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := readPgStartupMessage(bytes.NewReader(data))
		if err != nil {
			return
		}
		boundedPayload(t, data, payload)
		boundedText(t, data, parsePgStartupParams(payload))
	})
}

func FuzzParseTDSLogin7(f *testing.F) {
	f.Add(make([]byte, 94))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		u, p := parseTDSLogin7(data)
		boundedText(t, data, u, p)
	})
}

func FuzzParseDNSName(f *testing.F) {
	f.Add([]byte("\x07example\x03com\x00"), 0)
	f.Add([]byte{0xC0, 0x00}, 0)
	f.Fuzz(func(t *testing.T, data []byte, offset int) {
		name, next, ok := parseDNSName(data, offset)
		if !ok {
			return
		}
		if next < 0 || next > len(data) {
			t.Fatalf("next offset %d outside input of %d bytes", next, len(data))
		}
		boundedText(t, data, name)
	})
}

func FuzzParseMQTTConnect(f *testing.F) {
	f.Add([]byte("\x00\x04MQTT\x04\xc2\x00\x3c\x00\x02id\x00\x04user\x00\x04pass"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		id, u, p, _, err := parseMQTTConnect(data)
		if err != nil {
			return
		}
		boundedText(t, data, id, u, p)
	})
}

func FuzzReadTNSPacket(f *testing.F) {
	f.Add([]byte{0, 8, 0, 0, 1, 0, 0, 0})
	f.Add([]byte{0, 12, 0, 0, 1, 0, 0, 0, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, payload, err := readTNSPacket(bytes.NewReader(data))
		if err == nil {
			boundedPayload(t, data, payload)
		}
	})
}

func FuzzReadMySQLPacket(f *testing.F) {
	f.Add([]byte{3, 0, 0, 1, 'a', 'b', 'c'})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := readMySQLPacket(bytes.NewReader(data))
		if err == nil {
			boundedPayload(t, data, payload)
		}
	})
}

func FuzzReadMQTTVarInt(f *testing.F) {
	f.Add([]byte{0x7f})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := readMQTTVarInt(bytes.NewReader(data))
		if err == nil && (v < 0 || v > 268435455) {
			t.Fatalf("value %d out of MQTT range", v)
		}
	})
}

func FuzzHTTPMatchers(f *testing.F) {
	f.Add("/.env")
	f.Add("/a/../../etc/passwd")
	f.Add("${${lower:j}ndi:ldap://x/a}")
	f.Add("%24%7Bjndi:")
	f.Add("a/b c")
	f.Fuzz(func(t *testing.T, s string) {
		_ = matchExploitPath(s)
		_ = matchJNDI(s)
		if out := sanitizeHTTPValue(s); len(out) > maxHTTPValue || !utf8.ValidString(out) {
			t.Fatalf("sanitized value of %d bytes (valid utf8: %v)", len(out), utf8.ValidString(out))
		}
	})
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(helloSpec{
		version: 0x0303, ciphers: []uint16{0x1301, 0xc02b}, exts: []uint16{0, 10, 11, 13, 16, 43},
		sni: "example.com", curves: []uint16{29, 23}, points: []uint8{0}, sigAlgs: []uint16{0x0403},
		versions: []uint16{0x0304}, alpn: []string{"h2"},
	}.record())
	f.Add([]byte{0x16, 3, 1, 0, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		fp := fingerprintFromHello(data, "")
		boundedText(t, data, fp.SNI, fp.ALPN)
		if fp.JA3 != "" || fp.JA4 != "" {
			if len(fp.JA3) != 32 || len(fp.JA4) != 36 {
				t.Fatalf("ja3 %q ja4 %q", fp.JA3, fp.JA4)
			}
			if len(fp.SNI) > maxHTTPValue {
				t.Fatalf("sni of %d bytes", len(fp.SNI))
			}
		}
		h, err := parseClientHello(data)
		if err != nil {
			return
		}
		if len(h.Ciphers) > maxHelloCiphers || len(h.Extensions) > maxHelloExtensions || len(h.Curves) > maxHelloCurves ||
			len(h.Points) > maxHelloPoints || len(h.SigAlgs) > maxHelloSigAlgs || len(h.Versions) > maxHelloVersions || len(h.ALPN) > maxHelloALPN {
			t.Fatalf("unbounded lists in %+v", h)
		}
		boundedText(t, data, h.SNI)
	})
}

func FuzzParseKexInit(f *testing.F) {
	f.Add(buildKexInitStream("SSH-2.0-libssh_0.9.6", [8]string{"a,b", "c", "d", "e", "f", "g", "h", "i"}, 4))
	f.Add([]byte("SSH-2.0-x\r\n"))
	f.Add(append([]byte("SSH-2.0-x\r\n"), 0xff, 0xff, 0xff, 0xff, 4, 20))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, done := scanKexInit(data)
		if h != "" && (!done || len(h) != 32) {
			t.Fatalf("hassh %q done=%v", h, done)
		}
		if out := sanitizeClientVersion(string(data)); len(out) > maxSSHClientVersion || len(out) > len(data) {
			t.Fatalf("sanitized version of %d bytes from %d", len(out), len(data))
		}
		c := newKexSniffConn(nil)
		c.feed(data)
		if len(c.buf) > sshKexScanLimit {
			t.Fatalf("buffer of %d bytes", len(c.buf))
		}
	})
}

func FuzzReadMongoMessage(f *testing.F) {
	f.Add(mongoFrame(mongoOpMsg, 1, append([]byte{0, 0, 0, 0, 0}, newBSONDoc().i32("hello", 1).str("$db", "admin").bytes()...)))
	f.Add(opQuery("admin.$cmd", newBSONDoc().i32("isMaster", 1).bytes()))
	f.Add(opMsg(newBSONDoc().i32("saslStart", 1).str("mechanism", "SCRAM-SHA-256").binary("payload", []byte("n,,n=u,r=x")).bytes(), 0))
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0x07, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, body, err := readMongoMessage(bytes.NewReader(data))
		if err != nil {
			return
		}
		boundedPayload(t, data, body)
		if h.length > maxMongoMessage {
			t.Fatalf("message of %d bytes accepted", h.length)
		}
		req, err := parseMongoMessage(h, body)
		if err != nil {
			return
		}
		boundedPayload(t, data, req.payload)
		boundedText(t, data, req.command, req.db, req.mechanism, req.user, mongoSASLUser(req.payload))
		// The reply to any parsed request must be a frame the reader accepts.
		reply := mongoReply(req, h, 1, mongoErrorDoc("command "+commandName(req.command)+" requires authentication", 13, "Unauthorized"))
		if _, _, err := readMongoMessage(bytes.NewReader(reply)); err != nil {
			t.Fatalf("own reply rejected: %v", err)
		}
	})
}

func FuzzParseDockerBody(f *testing.F) {
	f.Add([]byte(`{"Image":"alpine","Cmd":["sh","-c","id"]}`))
	f.Add([]byte(`{"Image":"x","Entrypoint":"sh","Cmd":"id"}`))
	f.Add([]byte(`{"Cmd":[[["a"]],null,1]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		image, cmd := parseDockerBody(data)
		if len(image) > maxHTTPValue {
			t.Fatalf("image of %d bytes", len(image))
		}
		// Bounded by the item and byte caps; invalid UTF-8 may grow up to 3x when decoded.
		if limit := maxDockerCmdBytes + 4*len(data); len(cmd) > limit {
			t.Fatalf("cmd of %d bytes for %d input bytes", len(cmd), len(data))
		}
		if n := strings.Count(cmd, " ") + 1; n > 2*maxDockerCmdItems {
			t.Fatalf("%d words", n)
		}
		boundedText(t, data, sanitizeHTTPValue(image), sanitizeHTTPValue(cmd))
	})
}

func FuzzFormCommand(f *testing.F) {
	f.Add([]byte("cmd=id&cmd=whoami"))
	f.Add([]byte("command=sh&x=%zz&cmd=%"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		vals := formCommand(data)
		joined := joinStrings(vals, maxKubeCmdItems, maxKubeCmdBytes)
		if limit := maxKubeCmdBytes + len(data); len(joined) > limit {
			t.Fatalf("joined %d bytes for %d input bytes", len(joined), len(data))
		}
		boundedText(t, data, sanitizeHTTPValue(joined))
	})
}

func FuzzTelnetIAC(f *testing.F) {
	f.Add([]byte("\xff\xfb\x18root\r\n"))
	f.Add([]byte("\xff\xfa\x18\x00xterm\xff\xf0"))
	f.Add([]byte("\xff\xff\xff\xfd"))
	f.Add([]byte("\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		clean, replies, ttype := parseTelnetIAC(data)
		boundedPayload(t, data, clean)
		boundedPayload(t, data, replies)
		if len(replies) > maxTelnetReplyBytes || len(ttype) > maxTelnetTType {
			t.Fatalf("replies %d bytes, ttype %d bytes", len(replies), len(ttype))
		}
	})
}

func FuzzReadADBPacket(f *testing.F) {
	f.Add(adbPacket(adbCmdOPEN, 1, 0, []byte("shell:id")))
	f.Add(adbPacket(adbCmdAUTH, adbAuthPublicKey, 0, make([]byte, 64)))
	f.Add(make([]byte, adbHdrSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, payload, err := readADBPacket(bytes.NewReader(data))
		if err == nil {
			boundedPayload(t, data, payload)
		}
		if cmd, ok := adbShellCommand(payload); ok {
			boundedText(t, data, cmd)
			if len(cmd) > 256 {
				t.Fatalf("command of %d bytes", len(cmd))
			}
		}
	})
}

func FuzzParseModbusPDU(f *testing.F) {
	f.Add(byte(3), []byte{0, 1, 0xFF, 0xFF})
	f.Add(byte(23), make([]byte, 9))
	f.Add(byte(43), []byte{0x0E, 1, 0})
	f.Fuzz(func(t *testing.T, fc byte, data []byte) {
		attrs := parseModbusPDU(fc, data)
		if len(attrs) > 6 {
			t.Fatalf("%d attributes", len(attrs))
		}
		for _, a := range attrs {
			if (a.Key == "quantity" || a.Key == "write_quantity") && a.Value.Int64() > 2000 {
				t.Fatalf("%s = %d above the Modbus maximum", a.Key, a.Value.Int64())
			}
		}
		meta := modbusAlertMeta(attrs)
		if len(meta) > len(attrs) {
			t.Fatal("meta larger than attrs")
		}
	})
}

func FuzzSniffProtocol(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte("SSH-2.0-x"))
	f.Add([]byte{0, 0, 0, 0, 0xff, 'S', 'M', 'B'})
	f.Add([]byte{3, 0, 0, 0x13, 0x0e, 0xe0})
	f.Fuzz(func(t *testing.T, data []byte) {
		switch got := sniffProtocol(data); got {
		case sniffTLS, sniffHTTP, sniffSMB, sniffSSH, sniffRDP, sniffUnknown:
		default:
			t.Fatalf("label %q is outside the fixed set", got)
		}
		text := printableText(data)
		if len(text) != len(data) || strings.ContainsFunc(text, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			t.Fatalf("printableText(%x) = %q", data, text)
		}
	})
}

func FuzzParseJSONRPC(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"x","version":"1"}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"run_command","arguments":{"command":"id","n":[1],"o":{}}}}`))
	f.Add([]byte(`[{"jsonrpc":"2.0","method":"notifications/initialized"},{"bad":1},7,null]`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"abcabcabcabcabcabcabcabcabc","method":"ping"}`))
	f.Add([]byte(`[[[[[[`))
	f.Add([]byte("{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"a\u200b\\u202e\"}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := parseJSONRPC(data)
		if len(p.calls) > maxMCPBatch {
			t.Fatalf("%d calls", len(p.calls))
		}
		total := 0
		for _, c := range p.calls {
			if len(c.method) > maxMCPName || len(c.id) > maxMCPName+2 {
				t.Fatalf("method %d bytes, id %d bytes", len(c.method), len(c.id))
			}
			if !json.Valid(c.id) {
				t.Fatalf("id %q is not valid JSON", c.id)
			}
			tool, args, _ := mcpToolCall(c.params)
			if len(tool) > maxMCPName || len(args) > maxMCPArgsSummary {
				t.Fatalf("tool %d bytes, summary %d bytes", len(tool), len(args))
			}
			if strings.Count(args, "=") > maxMCPArgKeys+len(args)/maxMCPArgValue {
				t.Fatalf("too many keys in %q", args)
			}
			name, version := mcpClientInfo(c.params)
			total += len(c.method) + len(tool) + len(args) + len(name) + len(version) + len(mcpProtocolVersion(c.params))
		}
		if limit := maxMCPBatch * (4*len(data) + fuzzOutputSlack); total > limit {
			t.Fatalf("output of %d bytes for %d input bytes", total, len(data))
		}
	})
}
