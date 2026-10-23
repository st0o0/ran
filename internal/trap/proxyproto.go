package trap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/st0o0/ran/internal/metrics"
)

// maxProxyV1Len is the longest legal PROXY v1 header line including CRLF.
const maxProxyV1Len = 108

// maxProxyV2AddrLen caps the v2 address block before it is allocated. It is
// large enough for TCP6 plus TLVs and matches the reader buffer size.
const maxProxyV2AddrLen = 536

var v2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyHeaderTimeout bounds how long a new connection may take to send its
// PROXY header. With PROXY protocol enabled the header is required, so a
// connection that misses the deadline is dropped.
var proxyHeaderTimeout = 3 * time.Second

// maxPendingHandshakes bounds the connections that are waiting for a header
// or for the consumer to take them; further connections are closed at once.
var maxPendingHandshakes = 1024

// proxyHandoffTimeout bounds how long a handshaken connection waits for
// Accept, so a stalled consumer cannot pile up connections.
var proxyHandoffTimeout = 5 * time.Second

// proxyListener parses PROXY headers off the accept path: a background loop
// accepts raw connections and one goroutine per connection reads the header,
// so a silent peer never blocks other clients or Close.
type proxyListener struct {
	net.Listener
	logger   *slog.Logger
	metrics  *metrics.Metrics
	protocol string

	startOnce sync.Once
	closeOnce sync.Once
	ready     chan net.Conn
	done      chan struct{}
	acceptErr error
	failed    chan struct{}

	sem chan struct{}

	mu      sync.Mutex
	pending map[net.Conn]struct{}
}

func newProxyListener(ln net.Listener, logger *slog.Logger, m *metrics.Metrics, protocol string) *proxyListener {
	return &proxyListener{
		Listener: ln,
		logger:   logger,
		metrics:  m,
		protocol: protocol,
		ready:    make(chan net.Conn),
		done:     make(chan struct{}),
		failed:   make(chan struct{}),
		sem:      make(chan struct{}, maxPendingHandshakes),
		pending:  make(map[net.Conn]struct{}),
	}
}

func (pl *proxyListener) Accept() (net.Conn, error) {
	pl.startOnce.Do(func() { go pl.acceptLoop() })
	select {
	case conn := <-pl.ready:
		return conn, nil
	case <-pl.failed:
		return nil, pl.acceptErr
	case <-pl.done:
		return nil, net.ErrClosed
	}
}

func (pl *proxyListener) acceptLoop() {
	backoff := acceptPanicBackoffMin
	for {
		conn, err := pl.Listener.Accept()
		if err != nil {
			if !acceptRetryable(err) {
				pl.acceptErr = err
				close(pl.failed)
				return
			}
			// Transient error (for example EMFILE): back off and keep accepting.
			if pl.logger != nil {
				LogErrorStandalone(pl.logger, pl.protocol, "accept_failed", err)
			}
			select {
			case <-time.After(backoff):
			case <-pl.done:
				pl.acceptErr = net.ErrClosed
				close(pl.failed)
				return
			}
			if backoff *= 2; backoff > acceptPanicBackoffMax {
				backoff = acceptPanicBackoffMax
			}
			continue
		}
		backoff = acceptPanicBackoffMin
		select {
		case pl.sem <- struct{}{}:
			go pl.handshake(conn)
		default:
			// Too many pending handshakes: shed load instead of spawning more goroutines.
			pl.drop(conn, "handshake_limit")
		}
	}
}

// drop closes conn and counts it. The reason is logged at debug only.
func (pl *proxyListener) drop(conn net.Conn, reason string) {
	if pl.metrics != nil {
		pl.metrics.ProxyDropped.WithLabelValues(pl.protocol).Inc()
	}
	if pl.logger != nil {
		pl.logger.Debug("proxy protocol connection dropped", "protocol", pl.protocol, "reason", reason)
	}
	conn.Close()
}

// handshake reads the PROXY header under a deadline and hands the connection
// to Accept. The header is required: a connection without a valid one is
// closed and counted. It holds a semaphore slot until it is handed over.
func (pl *proxyListener) handshake(conn net.Conn) {
	defer func() { <-pl.sem }()
	pl.mu.Lock()
	select {
	case <-pl.done:
		pl.mu.Unlock()
		conn.Close()
		return
	default:
	}
	pl.pending[conn] = struct{}{}
	pl.mu.Unlock()

	var pc *proxyConn
	var err error
	safely(pl.logger, pl.metrics, pl.protocol, func() {
		_ = conn.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
		pc, err = newProxyConn(conn)
		_ = conn.SetReadDeadline(time.Time{})
	})

	pl.mu.Lock()
	delete(pl.pending, conn)
	pl.mu.Unlock()

	if pc == nil || err != nil {
		pl.drop(conn, "no_valid_header")
		return
	}
	timer := time.NewTimer(proxyHandoffTimeout)
	defer timer.Stop()
	select {
	case pl.ready <- pc:
	case <-pl.done:
		conn.Close()
	case <-timer.C:
		pl.drop(conn, "handoff_timeout")
	}
}

// Close stops accepting and closes connections still waiting for a header.
func (pl *proxyListener) Close() error {
	var err error
	pl.closeOnce.Do(func() {
		pl.mu.Lock()
		close(pl.done)
		for c := range pl.pending {
			c.Close()
		}
		pl.mu.Unlock()
		err = pl.Listener.Close()
	})
	return err
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
		return nil, fmt.Errorf("proxy proto: no header: %w", err)
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

	return nil, fmt.Errorf("proxy proto: missing header")
}

func parseV1(br *bufio.Reader) (net.Addr, error) {
	line, err := readLineLimited(br, maxProxyV1Len)
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

	srcIP, err := netip.ParseAddr(parts[2])
	if err != nil || srcIP.Zone() != "" {
		return nil, fmt.Errorf("invalid source address: %q", parts[2])
	}
	srcPort, err := strconv.ParseUint(parts[4], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid source port: %q", parts[4])
	}

	return &proxyAddr{
		network: "tcp",
		addr:    net.JoinHostPort(srcIP.String(), strconv.FormatUint(srcPort, 10)),
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

	if verCmd>>4 != 2 {
		return nil, fmt.Errorf("unsupported version: %d", verCmd>>4)
	}
	if addrLen > maxProxyV2AddrLen {
		return nil, fmt.Errorf("address block too long: %d", addrLen)
	}

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
