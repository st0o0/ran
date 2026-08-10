package trap

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func oracleTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Addrs:          map[string]string{"oracle": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestExtractTNSParam(t *testing.T) {
	data := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=sqlplus)))(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.1)(PORT=1521))(USER=scott))"

	user := extractTNSParam(data, "USER")
	if user != "scott" {
		t.Errorf("user = %q, want scott", user)
	}
	svc := extractTNSParam(data, "SERVICE_NAME")
	if svc != "ORCL" {
		t.Errorf("service_name = %q, want ORCL", svc)
	}
	missing := extractTNSParam(data, "NONEXISTENT")
	if missing != "" {
		t.Errorf("missing = %q, want empty", missing)
	}
}

func TestExtractTNSParamCaseInsensitive(t *testing.T) {
	data := "(description=(connect_data=(service_name=mydb))(user=Admin))"
	user := extractTNSParam(data, "USER")
	if user != "Admin" {
		t.Errorf("user = %q, want Admin", user)
	}
}

func TestBuildTNSPacket(t *testing.T) {
	payload := []byte("test payload")
	pkt := buildTNSPacket(1, payload)
	if len(pkt) != 8+len(payload) {
		t.Errorf("packet length = %d, want %d", len(pkt), 8+len(payload))
	}
	pktLen := binary.BigEndian.Uint16(pkt[0:2])
	if int(pktLen) != len(pkt) {
		t.Errorf("header length = %d, want %d", pktLen, len(pkt))
	}
	if pkt[4] != 1 {
		t.Errorf("type = %d, want 1", pkt[4])
	}
}

func TestOracleTrapConnection(t *testing.T) {
	cfg := oracleTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewOracle(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go trap.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.Addrs["oracle"], 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send TNS Connect packet
	connectData := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=sqlplus)))(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.1)(PORT=1521))(USER=scott))"
	conn.Write(buildTNSPacket(1, []byte(connectData)))

	// Read TNS Accept
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[4] != 2 {
		t.Errorf("accept type = %d, want 2", header[4])
	}
	acceptLen := int(binary.BigEndian.Uint16(header[0:2])) - 8
	if acceptLen > 0 {
		accept := make([]byte, acceptLen)
		if _, err := io.ReadFull(conn, accept); err != nil {
			t.Fatal(err)
		}
	}

	// Read TNS Refuse
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	if header[4] != 4 {
		t.Errorf("refuse type = %d, want 4", header[4])
	}
	refuseLen := int(binary.BigEndian.Uint16(header[0:2])) - 8
	refuse := make([]byte, refuseLen)
	if _, err := io.ReadFull(conn, refuse); err != nil {
		t.Fatal(err)
	}
	// Check that refuse data contains the ORA error
	refuseMsg := string(refuse[4:])
	if len(refuseMsg) == 0 {
		t.Error("refuse message is empty")
	}

	cancel()
	trap.Stop(context.Background())
}
