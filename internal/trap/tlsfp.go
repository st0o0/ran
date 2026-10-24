package trap

import (
	"crypto/md5" //nolint:gosec // JA3 is defined as an MD5 digest; it is a fingerprint, not a security primitive.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

// Bounds for everything taken from a ClientHello. The record is at most 16 KiB,
// so these caps only matter for hostile hellos; the fingerprints stay stable for
// real clients, which offer far fewer values.
const (
	maxHelloRecord     = 5 + 16384
	maxHelloCiphers    = 256
	maxHelloExtensions = 128
	maxHelloCurves     = 64
	maxHelloPoints     = 16
	maxHelloSigAlgs    = 128
	maxHelloVersions   = 32
	maxHelloALPN       = 16
)

// clientHello is the subset of a ClientHello that feeds JA3 and JA4. Every list
// is capped; GREASE values are kept here and dropped when hashing.
type clientHello struct {
	Version    uint16
	Ciphers    []uint16
	Extensions []uint16
	Curves     []uint16
	Points     []uint8
	SigAlgs    []uint16
	Versions   []uint16
	ALPN       []string
	SNI        string
	HasSNI     bool
}

var errBadHello = errors.New("malformed ClientHello")

// isGREASE reports RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// helloReader is a bounds-checked cursor; every read fails instead of panicking.
type helloReader struct {
	b   []byte
	bad bool
}

func (r *helloReader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *helloReader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *helloReader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func (r *helloReader) u24() int {
	if v := r.take(3); v != nil {
		return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
	}
	return 0
}

// parseClientHello parses a TLS record that carries a ClientHello. data starts
// at the record header and may be longer than the record. Only the first record
// is read: a ClientHello fragmented over several records is reported as
// malformed. Lists are capped, so the result is bounded regardless of the input.
func parseClientHello(data []byte) (*clientHello, error) {
	r := &helloReader{b: data}
	if r.u8() != 0x16 || r.u8() != 3 {
		return nil, errBadHello
	}
	r.u8() // record minor version
	rec := r.take(r.u16())
	if r.bad {
		return nil, errBadHello
	}
	r = &helloReader{b: rec}
	if r.u8() != 1 {
		return nil, errBadHello
	}
	body := r.take(r.u24())
	if r.bad {
		return nil, errBadHello
	}
	r = &helloReader{b: body}

	h := &clientHello{Version: uint16(r.u16())}
	r.take(32)
	r.take(r.u8())
	ciphers := r.take(r.u16())
	r.take(r.u8())
	if r.bad {
		return nil, errBadHello
	}
	for i := 0; i+1 < len(ciphers) && len(h.Ciphers) < maxHelloCiphers; i += 2 {
		h.Ciphers = append(h.Ciphers, binary.BigEndian.Uint16(ciphers[i:]))
	}
	if len(r.b) == 0 {
		return h, nil
	}
	exts := r.take(r.u16())
	if r.bad {
		return nil, errBadHello
	}
	r = &helloReader{b: exts}
	for len(r.b) > 0 && len(h.Extensions) < maxHelloExtensions {
		typ := uint16(r.u16())
		data := r.take(r.u16())
		if r.bad {
			return nil, errBadHello
		}
		h.Extensions = append(h.Extensions, typ)
		h.parseExtension(typ, data)
	}
	return h, nil
}

// parseExtension reads the extensions JA3 and JA4 need. Malformed extension
// bodies are ignored; the extension type is still recorded by the caller.
func (h *clientHello) parseExtension(typ uint16, data []byte) {
	r := &helloReader{b: data}
	switch typ {
	case 0: // server_name
		list := &helloReader{b: r.take(r.u16())}
		h.HasSNI = true
		for len(list.b) > 0 && !list.bad {
			nameType := list.u8()
			name := list.take(list.u16())
			if !list.bad && nameType == 0 && h.SNI == "" {
				h.SNI = string(name)
			}
		}
	case 10: // supported_groups
		list := r.take(r.u16())
		for i := 0; i+1 < len(list) && len(h.Curves) < maxHelloCurves; i += 2 {
			h.Curves = append(h.Curves, binary.BigEndian.Uint16(list[i:]))
		}
	case 11: // ec_point_formats
		list := r.take(r.u8())
		for i := 0; i < len(list) && len(h.Points) < maxHelloPoints; i++ {
			h.Points = append(h.Points, list[i])
		}
	case 13: // signature_algorithms
		list := r.take(r.u16())
		for i := 0; i+1 < len(list) && len(h.SigAlgs) < maxHelloSigAlgs; i += 2 {
			h.SigAlgs = append(h.SigAlgs, binary.BigEndian.Uint16(list[i:]))
		}
	case 16: // application_layer_protocol_negotiation
		list := &helloReader{b: r.take(r.u16())}
		for len(list.b) > 0 && !list.bad && len(h.ALPN) < maxHelloALPN {
			if p := list.take(list.u8()); !list.bad {
				h.ALPN = append(h.ALPN, string(p))
			}
		}
	case 43: // supported_versions
		list := r.take(r.u8())
		for i := 0; i+1 < len(list) && len(h.Versions) < maxHelloVersions; i += 2 {
			h.Versions = append(h.Versions, binary.BigEndian.Uint16(list[i:]))
		}
	}
}

func joinU16(vals []uint16, f func(uint16) string) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			parts = append(parts, f(v))
		}
	}
	return strings.Join(parts, "-")
}

func dec(v uint16) string { return strconv.Itoa(int(v)) }

// ja3 returns the JA3 hash: MD5 over version, ciphers, extensions, groups and
// point formats, each list in wire order with GREASE removed.
func (h *clientHello) ja3() string {
	points := make([]string, 0, len(h.Points))
	for _, p := range h.Points {
		points = append(points, strconv.Itoa(int(p)))
	}
	s := strings.Join([]string{
		dec(h.Version),
		joinU16(h.Ciphers, dec),
		joinU16(h.Extensions, dec),
		joinU16(h.Curves, dec),
		strings.Join(points, "-"),
	}, ",")
	sum := md5.Sum([]byte(s)) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}

func hex4(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>12], digits[v>>8&0xf], digits[v>>4&0xf], digits[v&0xf]})
}

// ja4Version maps the TLS version to the two character JA4 code. Per the JA4
// spec the highest non-GREASE value of supported_versions is used when that
// extension is present, otherwise the legacy handshake version.
func (h *clientHello) ja4Version() string {
	v := h.Version
	best := uint16(0)
	for _, sv := range h.Versions {
		if !isGREASE(sv) && sv > best {
			best = sv
		}
	}
	if best != 0 {
		v = best
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// ja4ALPN returns the two JA4 ALPN characters of the first ALPN value. If its
// first or last byte is not ASCII alphanumeric, both characters come from the hex
// form of the value instead: the first hex digit of the first byte and the last
// hex digit of the last byte (0x20 0x61 gives "21", 0xAB 0xCD gives "ad").
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || len(alpn[0]) == 0 {
		return "00"
	}
	p := alpn[0]
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	const digits = "0123456789abcdef"
	return string([]byte{digits[first>>4], digits[last&0xf]})
}

func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

func sortU16(v []uint16) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j-1] > v[j]; j-- {
			v[j-1], v[j] = v[j], v[j-1]
		}
	}
}

func hex12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ja4 returns the JA4 string (TCP flavour, "t" prefix) for this hello.
func (h *clientHello) ja4() string {
	ciphers := make([]uint16, 0, len(h.Ciphers))
	for _, c := range h.Ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	exts := make([]uint16, 0, len(h.Extensions))
	hashed := make([]uint16, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		if isGREASE(e) {
			continue
		}
		exts = append(exts, e)
		if e != 0 && e != 16 {
			hashed = append(hashed, e)
		}
	}
	sni := byte('i')
	if h.HasSNI {
		sni = 'd'
	}
	sortU16(ciphers)
	sortU16(hashed)
	cs := make([]string, len(ciphers))
	for i, c := range ciphers {
		cs[i] = hex4(c)
	}
	es := make([]string, len(hashed))
	for i, e := range hashed {
		es[i] = hex4(e)
	}
	sa := make([]string, 0, len(h.SigAlgs))
	for _, s := range h.SigAlgs {
		if !isGREASE(s) {
			sa = append(sa, hex4(s))
		}
	}
	extPart := strings.Join(es, ",")
	if len(sa) > 0 {
		extPart += "_" + strings.Join(sa, ",")
	}
	if len(es) == 0 {
		extPart = ""
	}

	return "t" + h.ja4Version() + string(sni) + count2(len(ciphers)) + count2(len(exts)) + ja4ALPN(h.ALPN) +
		"_" + hex12(strings.Join(cs, ",")) + "_" + hex12(extPart)
}

// tlsFingerprint is what the HTTPS trap records for one connection. JA3 and JA4
// are empty when the hello could not be parsed.
type tlsFingerprint struct {
	SNI  string
	JA3  string
	JA4  string
	ALPN string
}

func fingerprintFromHello(raw []byte, serverName string) *tlsFingerprint {
	fp := &tlsFingerprint{SNI: sanitizeHTTPValue(serverName)}
	h, err := parseClientHello(raw)
	if err != nil {
		return fp
	}
	if fp.SNI == "" {
		fp.SNI = sanitizeHTTPValue(h.SNI)
	}
	fp.JA3 = h.ja3()
	fp.JA4 = h.ja4()
	fp.ALPN = sanitizeHTTPValue(strings.Join(h.ALPN, ","))
	return fp
}

// helloConn records the first TLS record the client sends (at most
// maxHelloRecord bytes) so the ClientHello can be fingerprinted, including the
// extension order that tls.ClientHelloInfo does not expose. Reads are serialized
// by tls.Conn, and the capture is finished before GetConfigForClient runs, so
// no locking is needed.
type helloConn struct {
	net.Conn
	buf  []byte
	done bool

	fp      atomic.Pointer[tlsFingerprint]
	onHello func(*tlsFingerprint)
}

func (c *helloConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.done && n > 0 {
		c.capture(p[:n])
	}
	return n, err
}

func (c *helloConn) capture(p []byte) {
	room := maxHelloRecord - len(c.buf)
	if len(p) > room {
		p = p[:room]
	}
	c.buf = append(c.buf, p...)
	if len(c.buf) < 5 {
		return
	}
	need := 5 + int(binary.BigEndian.Uint16(c.buf[3:5]))
	if c.buf[0] != 0x16 || need > maxHelloRecord {
		c.done, c.buf = true, nil
		return
	}
	if len(c.buf) >= need {
		c.done = true
		c.buf = c.buf[:need]
	}
}

// finish fingerprints the captured hello and publishes the result.
func (c *helloConn) finish(serverName string) {
	fp := fingerprintFromHello(c.buf, serverName)
	c.buf = nil
	c.fp.Store(fp)
	if c.onHello != nil {
		c.onHello(fp)
	}
}
