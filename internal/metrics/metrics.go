package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Connections         *prometheus.CounterVec
	CredentialsCaptured *prometheus.CounterVec
	ActiveSessions      *prometheus.GaugeVec
	SessionDuration     *prometheus.HistogramVec
	CrowdSecAlerts      *prometheus.CounterVec
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Connections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_connections_total",
			Help: "Total number of trap connections.",
		}, []string{"protocol"}),
		CredentialsCaptured: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_credentials_captured_total",
			Help: "Total number of captured credential attempts.",
		}, []string{"protocol"}),
		ActiveSessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ran_active_sessions",
			Help: "Number of currently active trap sessions.",
		}, []string{"protocol"}),
		SessionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ran_session_duration_seconds",
			Help:    "Duration of trap sessions in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"protocol"}),
		CrowdSecAlerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_crowdsec_alerts_total",
			Help: "Total number of CrowdSec alert pushes.",
		}, []string{"protocol", "status"}),
	}
	reg.MustRegister(m.Connections, m.CredentialsCaptured, m.ActiveSessions, m.SessionDuration, m.CrowdSecAlerts)
	return m
}
