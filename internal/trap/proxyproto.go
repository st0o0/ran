package trap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

var v2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

type proxyListener struct {
	net.Listener
}

func (pl *proxyListener) Accept() (net.Conn, error) {
	conn, err := pl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newProxyConn(conn)
}

type proxyAddr struct {
	network string
	addr    string
}

func (a *proxyAddr) Network() string { return a.network }
func (a *proxyAddr) String() string  { return a.addr }

type proxyConn struct {
	net.Conn
	reader  *bufio.Reader
	srcAddr net.Addr
}

func (c *proxyConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *proxyConn) RemoteAddr() net.Addr {
	if c.srcAddr != nil {
		return c.srcAddr
	}
	return c.Conn.RemoteAddr()
}

func newProxyConn(conn net.Conn) (*proxyConn, error) {
	br := bufio.NewReaderSize(conn, 536)
	pc := &proxyConn{Conn: conn, reader: br}

	peek, err := br.Peek(12)
	if err != nil {
		return pc, nil
	}

	if bytes.Equal(peek, v2Signature) {
		src, err := parseV2(br)
		if err != nil {
			return nil, fmt.Errorf("proxy proto v2: %w", err)
		}
		if src != nil {
			pc.srcAddr = src
		}
		return pc, nil
	}

	if len(peek) >= 6 && string(peek[:6]) == "PROXY " {
		src, err := parseV1(br)
		if err != nil {
			return nil, fmt.Errorf("proxy proto v1: %w", err)
		}
		if src != nil {
			pc.srcAddr = src
		}
		return pc, nil
	}

	return pc, nil
}

func parseV1(br *bufio.Reader) (net.Addr, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")

	// PROXY TCP4 <src> <dst> <srcport> <dstport>
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid header: %q", line)
	}

	if parts[1] == "UNKNOWN" {
		return nil, nil
	}

	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid header: %q", line)
	}

	srcPort, err := strconv.Atoi(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid source port: %q", parts[4])
	}

	return &proxyAddr{
		network: "tcp",
		addr:    net.JoinHostPort(parts[2], strconv.Itoa(srcPort)),
	}, nil
}

func parseV2(br *bufio.Reader) (net.Addr, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}

	verCmd := hdr[12]
	family := hdr[13]
	addrLen := binary.BigEndian.Uint16(hdr[14:16])

	addrData := make([]byte, addrLen)
	if _, err := io.ReadFull(br, addrData); err != nil {
		return nil, err
	}

	cmd := verCmd & 0x0F
	if cmd == 0x00 { // LOCAL
		return nil, nil
	}
	if cmd != 0x01 { // PROXY
		return nil, fmt.Errorf("unknown command: %d", cmd)
	}

	switch family {
	case 0x11: // TCP4
		if len(addrData) < 12 {
			return nil, fmt.Errorf("tcp4 addr too short")
		}
		srcIP := net.IP(addrData[0:4])
		srcPort := binary.BigEndian.Uint16(addrData[8:10])
		return &proxyAddr{
			network: "tcp",
			addr:    net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort))),
		}, nil

	case 0x21: // TCP6
		if len(addrData) < 36 {
			return nil, fmt.Errorf("tcp6 addr too short")
		}
		srcIP := net.IP(addrData[0:16])
		srcPort := binary.BigEndian.Uint16(addrData[32:34])
		return &proxyAddr{
			network: "tcp",
			addr:    net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort))),
		}, nil

	default:
		return nil, nil
	}
}
