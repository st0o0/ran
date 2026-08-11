package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNew(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	if m.Connections == nil {
		t.Error("Connections is nil")
	}
	if m.CredentialsCaptured == nil {
		t.Error("CredentialsCaptured is nil")
	}
	if m.ActiveSessions == nil {
		t.Error("ActiveSessions is nil")
	}
	if m.SessionDuration == nil {
		t.Error("SessionDuration is nil")
	}
	if m.CrowdSecAlerts == nil {
		t.Error("CrowdSecAlerts is nil")
	}

	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gather error: %v", err)
	}

	m.Connections.WithLabelValues("ssh").Inc()
	m.CredentialsCaptured.WithLabelValues("ssh").Inc()
	m.ActiveSessions.WithLabelValues("ssh").Set(1)
	m.SessionDuration.WithLabelValues("ssh").Observe(1.5)
	m.CrowdSecAlerts.WithLabelValues("ssh", "success").Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}
	if len(families) != 5 {
		t.Errorf("got %d metric families, want 5", len(families))
	}
}

func TestNewSeparateRegistries(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	reg2 := prometheus.NewRegistry()

	m1 := New(reg1)
	m2 := New(reg2)

	if m1 == nil || m2 == nil {
		t.Fatal("New should not return nil")
	}
}
