package trap

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestProxyV1TCP4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 192.168.1.100 10.0.0.1 56324 8080\r\n"))
		_, _ = client.Write([]byte("hello"))
	}()

	pc, err := newProxyConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	host, port := ParseAddr(pc.RemoteAddr().String())
	if host != "192.168.1.100" {
		t.Errorf("host = %q, want 192.168.1.100", host)
	}
	if port != 56324 {
		t.Errorf("port = %d, want 56324", port)
	}

	buf := make([]byte, 5)
	if _, err := io.ReadFull(pc, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Errorf("payload = %q, want hello", buf)
	}
}

func TestProxyV1TCP6(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("PROXY TCP6 2001:db8::1 ::1 45678 80\r\n"))
	}()

	pc, err := newProxyConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	host, port := ParseAddr(pc.RemoteAddr().String())
	if host != "2001:db8::1" {
		t.Errorf("host = %q, want 2001:db8::1", host)
	}
	if port != 45678 {
		t.Errorf("port = %d, want 45678", port)
	}
}

func TestProxyV1Unknown(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("PROXY UNKNOWN\r\n"))
		_, _ = client.Write([]byte("data"))
	}()

	pc, err := newProxyConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if pc.RemoteAddr().String() != server.RemoteAddr().String() {
		t.Error("UNKNOWN should fall back to conn RemoteAddr")
	}
}

func TestProxyV2TCP4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		// v2 header
		var hdr [16]byte
		copy(hdr[:12], v2Signature)
		hdr[12] = 0x21 // version 2, PROXY command
		hdr[13] = 0x11 // TCP4
		binary.BigEndian.PutUint16(hdr[14:16], 12) // addr len

		var addr [12]byte
		copy(addr[0:4], net.ParseIP("10.20.30.40").To4())  // src
		copy(addr[4:8], net.ParseIP("192.168.1.1").To4())   // dst
		binary.BigEndian.PutUint16(addr[8:10], 12345)       // src port
		binary.BigEndian.PutUint16(addr[10:12], 443)        // dst port

		_, _ = client.Write(hdr[:])
		_, _ = client.Write(addr[:])
		_, _ = client.Write([]byte("payload"))
	}()

	pc, err := newProxyConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	host, port := ParseAddr(pc.RemoteAddr().String())
	if host != "10.20.30.40" {
		t.Errorf("host = %q, want 10.20.30.40", host)
	}
	if port != 12345 {
		t.Errorf("port = %d, want 12345", port)
	}

	buf := make([]byte, 7)
	if _, err := io.ReadFull(pc, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "payload" {
		t.Errorf("payload = %q, want payload", buf)
	}
}

func TestProxyV2Local(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		var hdr [16]byte
		copy(hdr[:12], v2Signature)
		hdr[12] = 0x20 // version 2, LOCAL command
		hdr[13] = 0x00
		binary.BigEndian.PutUint16(hdr[14:16], 0) // no addr

		_, _ = client.Write(hdr[:])
		_, _ = client.Write([]byte("data"))
	}()

	pc, err := newProxyConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if pc.RemoteAddr().String() != server.RemoteAddr().String() {
		t.Error("LOCAL should fall back to conn RemoteAddr")
	}
}

func TestNoProxyProtocol(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	pc, err := newProxyConn(server)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if pc.RemoteAddr().String() != server.RemoteAddr().String() {
		t.Error("no PROXY header should use original RemoteAddr")
	}

	buf := make([]byte, 3)
	if _, err := io.ReadFull(pc, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "GET" {
		t.Errorf("payload = %q, want GET", buf)
	}
}
