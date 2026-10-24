package trap

import (
	"bytes"
	"crypto/md5" //nolint:gosec // HASSH is defined as an MD5 fingerprint, not a security primitive
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"sync"
)

const (
	// maxSSHClientVersion bounds the client version string (RFC 4253 limits the
	// identification line to 255 bytes).
	maxSSHClientVersion = 255
	// sshKexScanLimit bounds how many client bytes are buffered while looking
	// for the first KEXINIT. A KEXINIT is typically about 1 to 2 KiB.
	sshKexScanLimit = 16 * 1024
	sshMsgKexInit   = 20
)

// sanitizeClientVersion keeps printable ASCII only and cuts the value to
// maxSSHClientVersion bytes.
func sanitizeClientVersion(v string) string {
	var b strings.Builder
	for i := 0; i < len(v) && b.Len() < maxSSHClientVersion; i++ {
		if c := v[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// hasshOf returns the HASSH of a client KEXINIT name-list set: the MD5 of
// "kex;enc_c2s;mac_c2s;comp_c2s" as defined by the Salesforce HASSH spec.
func hasshOf(kex, enc, mac, comp string) string {
	sum := md5.Sum([]byte(kex + ";" + enc + ";" + mac + ";" + comp)) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}

// scanKexInit looks for the first SSH_MSG_KEXINIT in the client byte stream
// (identification line followed by unencrypted binary packets). It returns
// the HASSH, or "" with done=false while more bytes are needed, or "" with
// done=true if the stream is not parseable. It never allocates from a length
// field; buf is the bytes seen so far and is already bounded by the caller.
func scanKexInit(buf []byte) (hassh string, done bool) {
	// Identification: skip non-SSH lines, then the SSH- line.
	pos := 0
	for {
		nl := bytes.IndexByte(buf[pos:], '\n')
		if nl < 0 {
			return "", false
		}
		line := buf[pos : pos+nl]
		pos += nl + 1
		if bytes.HasPrefix(line, []byte("SSH-")) {
			break
		}
	}
	rest := buf[pos:]
	if len(rest) < 6 {
		return "", false
	}
	pktLen := binary.BigEndian.Uint32(rest[:4])
	padLen := int(rest[4])
	if pktLen < 2 || pktLen > sshKexScanLimit || padLen+1 > int(pktLen) {
		return "", true
	}
	if len(rest) < 4+int(pktLen) {
		return "", false
	}
	payload := rest[5 : 4+int(pktLen)-padLen]
	if len(payload) < 1+16 || payload[0] != sshMsgKexInit {
		return "", true
	}
	p := payload[17:]
	var lists [8]string
	for i := range lists {
		if len(p) < 4 {
			return "", true
		}
		n := binary.BigEndian.Uint32(p[:4])
		p = p[4:]
		if uint64(n) > uint64(len(p)) {
			return "", true
		}
		lists[i] = string(p[:n])
		p = p[n:]
	}
	return hasshOf(lists[0], lists[2], lists[4], lists[6]), true
}

// kexSniffConn is a read-only tap on the client byte stream: bytes are passed
// through unchanged and copied into a bounded buffer until the first KEXINIT
// was parsed. It has no effect on the handshake.
type kexSniffConn struct {
	net.Conn
	mu    sync.Mutex
	buf   []byte
	done  bool
	hassh string
}

func newKexSniffConn(c net.Conn) *kexSniffConn {
	return &kexSniffConn{Conn: c}
}

func (c *kexSniffConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.feed(p[:n])
	}
	return n, err
}

func (c *kexSniffConn) feed(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	if room := sshKexScanLimit - len(c.buf); len(b) > room {
		b = b[:room]
	}
	c.buf = append(c.buf, b...)
	h, done := scanKexInit(c.buf)
	if !done && len(c.buf) >= sshKexScanLimit {
		done = true
	}
	if done {
		c.hassh = h
		c.done = true
		c.buf = nil
	}
}

func (c *kexSniffConn) HASSH() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hassh
}
