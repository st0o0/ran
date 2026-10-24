package trap

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

type depthTrap struct {
	addr string
	sink *eventSink
	m    *metrics.Metrics
	logs *syncBuffer
}

// startDepthTrap starts a trap on port 0 wired to a real Sensor with a recording
// sink. tweak adjusts the config before the trap is built.
func startDepthTrap(t *testing.T, name string, tweak func(*config.Config), build trapBuilder) *depthTrap {
	t.Helper()
	cfg := &config.Config{
		Addrs:          map[string]string{name: "127.0.0.1:0"},
		PerProto:       map[string]config.ProtoConfig{},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
		MaxAuthRetries: 3,
	}
	if tweak != nil {
		tweak(cfg)
	}
	logs := &syncBuffer{}
	sink := &eventSink{}
	sensor := alert.NewSensor(alert.SensorConfig{SummaryWindow: time.Hour}, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m := metrics.New(prometheus.NewRegistry(), "test")
	tr := build(cfg, newJSONLogger(logs), m, NewLimiter(cfg.MaxSessions, cfg.MaxPerIP), sensor)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(sensor.Close)
	t.Cleanup(cancel)
	return &depthTrap{addr: serveTrap(t, ctx, tr), sink: sink, m: m, logs: logs}
}

// credentials returns the credential counter of the trap's protocol.
func (d *depthTrap) credentials(proto string) float64 {
	var c dto.Metric
	if err := d.m.CredentialsCaptured.WithLabelValues(proto).Write(&c); err != nil {
		return -1
	}
	return c.GetCounter().GetValue()
}

// waitCredentials waits until n credentials were captured.
func (d *depthTrap) waitCredentials(t *testing.T, proto string, n float64) {
	t.Helper()
	waitUntil(t, func() bool { return d.credentials(proto) >= n })
}

// waitOutcomeLabel waits until a session of proto ended with the given outcome.
func (d *depthTrap) waitOutcomeLabel(t *testing.T, proto, outcome string) {
	t.Helper()
	waitUntil(t, func() bool {
		var c dto.Metric
		if err := d.m.Connections.WithLabelValues(proto, outcome).Write(&c); err != nil {
			return false
		}
		return c.GetCounter().GetValue() >= 1
	})
}
