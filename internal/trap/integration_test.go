package trap_test

import (
	"bytes"
	"context"
	"encoding/binary"
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
		SSH:            true,
		HTTP:           true,
		MySQL:          true,
		SSHAddr:        sshAddr,
		HTTPAddr:       httpAddr,
		MySQLAddr:      mysqlAddr,
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
