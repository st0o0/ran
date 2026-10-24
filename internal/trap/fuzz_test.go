package trap

import (
	"bufio"
	"bytes"
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
