package trap

import (
	"context"
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

func TestSNMPTrap(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()

	cfg := &config.Config{
		Addrs:          map[string]string{"snmp": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New(prometheus.NewRegistry())
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	alerter := alert.NoopAlerter{}

	tr := NewSNMP(cfg, logger, m, limiter, alerter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Build SNMPv2c GetRequest packet
	requestID := berInteger(1)
	errorStatus := berInteger(0)
	errorIndex := berInteger(0)
	varbindList := berSequence(nil)

	pduContents := make([]byte, 0, len(requestID)+len(errorStatus)+len(errorIndex)+len(varbindList))
	pduContents = append(pduContents, requestID...)
	pduContents = append(pduContents, errorStatus...)
	pduContents = append(pduContents, errorIndex...)
	pduContents = append(pduContents, varbindList...)

	getRequest := append([]byte{0xA0}, berLength(len(pduContents))...)
	getRequest = append(getRequest, pduContents...)

	version := berInteger(1) // v2c
	community := berOctetString([]byte("public"))

	seqContents := make([]byte, 0, len(version)+len(community)+len(getRequest))
	seqContents = append(seqContents, version...)
	seqContents = append(seqContents, community...)
	seqContents = append(seqContents, getRequest...)

	packet := berSequence(seqContents)

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, err = c.Write(packet)
	if err != nil {
		t.Fatal(err)
	}

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := c.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	resp = resp[:n]

	if resp[0] != 0x30 {
		t.Fatalf("response does not start with SEQUENCE tag, got 0x%02x", resp[0])
	}

	foundGetResponse := false
	foundErrorStatus := false
	for i := 0; i < len(resp)-2; i++ {
		if resp[i] == 0xA2 {
			foundGetResponse = true
		}
		if resp[i] == 0x02 && resp[i+1] == 0x01 && resp[i+2] == 0x02 {
			foundErrorStatus = true
		}
	}

	if !foundGetResponse {
		t.Error("response does not contain GetResponse tag (0xA2)")
	}
	if !foundErrorStatus {
		t.Error("response does not contain error-status noSuchName (2)")
	}

	cancel()
	tr.Stop(context.Background())
}
