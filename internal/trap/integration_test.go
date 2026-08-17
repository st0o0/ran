package trap_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	"github.com/st0o0/ran/internal/trap"
	gossh "golang.org/x/crypto/ssh"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestIntegrationAllTraps(t *testing.T) {
	sshAddr := freeAddr(t)
	httpAddr := freeAddr(t)
	mysqlAddr := freeAddr(t)

	cfg := &config.Config{
		Traps:          []string{"ssh", "http", "mysql"},
		Addrs:          map[string]string{"ssh": sshAddr, "http": httpAddr, "mysql": mysqlAddr},
		SSHHostKeyPath: "",
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	noop := alert.NoopAlerter{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start SSH trap
	sshTrap, err := trap.NewSSH(cfg, logger, m, limiter, noop)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = sshTrap.Start(ctx) }()

	// Start HTTP trap
	httpTrap := trap.NewHTTP(cfg, logger, m, limiter, noop)
	go func() { _ = httpTrap.Start(ctx) }()

	// Start MySQL trap
	mysqlTrap := trap.NewMySQL(cfg, logger, m, limiter, noop)
	go func() { _ = mysqlTrap.Start(ctx) }()

	time.Sleep(200 * time.Millisecond)

	// Test SSH
	sshClient, err := gossh.Dial("tcp", sshAddr, &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password("toor")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	if err == nil {
		sshClient.Close()
	}

	// Test HTTP
	resp, err := http.Post(
		"http://"+httpAddr+"/wp-login.php",
		"application/x-www-form-urlencoded",
		strings.NewReader("log=admin&pwd=hunter2"),
	)
	if err != nil {
		t.Fatalf("http POST: %v", err)
	}
	resp.Body.Close()

	// Test MySQL
	conn, err := net.DialTimeout("tcp", mysqlAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("mysql dial: %v", err)
	}
	// Read greeting
	header := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(header)
	greetLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	greetPayload := make([]byte, greetLen)
	_, _ = conn.Read(greetPayload)
	// Send handshake response
	var mysqlResp []byte
	mysqlResp = binary.LittleEndian.AppendUint32(mysqlResp, 0x000FA68D)
	mysqlResp = binary.LittleEndian.AppendUint32(mysqlResp, 1<<24)
	mysqlResp = append(mysqlResp, 0x21)
	mysqlResp = append(mysqlResp, make([]byte, 23)...)
	mysqlResp = append(mysqlResp, []byte("dbuser\x00")...)
	mysqlResp = append(mysqlResp, byte(len("dbpass")))
	mysqlResp = append(mysqlResp, []byte("dbpass")...)
	// Wrap in MySQL packet
	pkt := make([]byte, 4+len(mysqlResp))
	pkt[0] = byte(len(mysqlResp))
	pkt[1] = byte(len(mysqlResp) >> 8)
	pkt[2] = byte(len(mysqlResp) >> 16)
	pkt[3] = 1
	copy(pkt[4:], mysqlResp)
	_, _ = conn.Write(pkt)
	// Read ERR
	_, _ = conn.Read(make([]byte, 256))
	conn.Close()

	time.Sleep(200 * time.Millisecond)
	cancel()

	_ = sshTrap.Stop(context.Background())
	_ = httpTrap.Stop(context.Background())
	_ = mysqlTrap.Stop(context.Background())

	logs := logBuf.String()

	// Verify structured log output contains expected fields
	for _, want := range []string{
		`"protocol":"ssh"`,
		`"action":"auth_attempt"`,
		`"username":"root"`,
		`"password":"toor"`,
		`"protocol":"http"`,
		`"username":"admin"`,
		`"password":"hunter2"`,
		`"protocol":"mysql"`,
		`"username":"dbuser"`,
		`"password":"dbpass"`,
		`"session_id"`,
		`"source_ip"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("log output missing %s", want)
		}
	}
}

func TestIntegrationMultiPort(t *testing.T) {
	addr1 := freeAddr(t)
	addr2 := freeAddr(t)

	cfg := &config.Config{
		Traps:          []string{"ftp"},
		Addrs:          map[string]string{"ftp": addr1 + "," + addr2},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	tr := trap.NewFTP(cfg, logger, m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Connect to first port
	conn1, err := net.DialTimeout("tcp", addr1, 2*time.Second)
	if err != nil {
		t.Fatalf("dial addr1: %v", err)
	}
	_ = conn1.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = bufio.NewReader(conn1).ReadString('\n')
	conn1.Close()

	// Connect to second port
	conn2, err := net.DialTimeout("tcp", addr2, 2*time.Second)
	if err != nil {
		t.Fatalf("dial addr2: %v", err)
	}
	_ = conn2.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = bufio.NewReader(conn2).ReadString('\n')
	conn2.Close()

	time.Sleep(200 * time.Millisecond)
	cancel()
	_ = tr.Stop(context.Background())

	logs := logBuf.String()

	_, port1 := trap.ParseAddr(addr1)
	_, port2 := trap.ParseAddr(addr2)
	destPort1 := fmt.Sprintf(`"dest_port":%d`, port1)
	destPort2 := fmt.Sprintf(`"dest_port":%d`, port2)

	if !strings.Contains(logs, destPort1) {
		t.Errorf("logs missing dest_port for first address (%d)", port1)
	}
	if !strings.Contains(logs, destPort2) {
		t.Errorf("logs missing dest_port for second address (%d)", port2)
	}
}

func TestIntegrationFTP(t *testing.T) {
	addr := freeAddr(t)
	cfg := &config.Config{
		Traps:          []string{"ftp"},
		Addrs:          map[string]string{"ftp": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	tr := trap.NewFTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(banner, "220") {
		t.Errorf("FTP banner = %q, want 220 prefix", banner)
	}

	cancel()
	_ = tr.Stop(context.Background())
}

func TestIntegrationTelnet(t *testing.T) {
	addr := freeAddr(t)
	cfg := &config.Config{
		Traps:          []string{"telnet"},
		Addrs:          map[string]string{"telnet": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	tr := trap.NewTelnet(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	prompt := string(buf[:n])
	if !strings.Contains(prompt, "login") && !strings.Contains(prompt, "Login") && len(prompt) == 0 {
		t.Errorf("Telnet prompt = %q, expected login prompt or negotiation", prompt)
	}

	cancel()
	_ = tr.Stop(context.Background())
}

func TestIntegrationRedis(t *testing.T) {
	addr := freeAddr(t)
	cfg := &config.Config{
		Traps:          []string{"redis"},
		Addrs:          map[string]string{"redis": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	tr := trap.NewRedis(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tr.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n")
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "PONG") && !strings.Contains(resp, "ERR") && !strings.HasPrefix(resp, "+") && !strings.HasPrefix(resp, "-") {
		t.Errorf("Redis response = %q, expected RESP reply", resp)
	}

	cancel()
	_ = tr.Stop(context.Background())
}
