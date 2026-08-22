package metrics

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	Connections         *prometheus.CounterVec
	CredentialsCaptured *prometheus.CounterVec
	ActiveSessions      *prometheus.GaugeVec
	SessionDuration     *prometheus.HistogramVec
	CrowdSecPipeline    *prometheus.CounterVec
	CrowdSecDropped     *prometheus.CounterVec
}

func New(reg prometheus.Registerer, version string) *Metrics {
	m := &Metrics{
		Connections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_connections_total",
			Help: "Total number of trap connections.",
		}, []string{"protocol", "outcome"}),
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
		CrowdSecPipeline: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_crowdsec_pipeline_total",
			Help: "Total number of CrowdSec alert pipeline events.",
		}, []string{"protocol", "stage"}),
		CrowdSecDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_crowdsec_alerts_dropped_total",
			Help: "Total number of CrowdSec alerts dropped due to full channel.",
		}, []string{"protocol"}),
	}

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ran_build_info",
		Help: "Build information for ran.",
	}, []string{"version", "goversion"})
	buildInfo.WithLabelValues(version, runtime.Version()).Set(1)

	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(m.Connections, m.CredentialsCaptured, m.ActiveSessions, m.SessionDuration, m.CrowdSecPipeline, m.CrowdSecDropped, buildInfo)
	return m
}
