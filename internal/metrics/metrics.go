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
	PanicsRecovered     *prometheus.CounterVec
	ProxyDropped        *prometheus.CounterVec
	UDPRateLimited      *prometheus.CounterVec
	IgnoredSessions     *prometheus.CounterVec

	CrowdSecPushDuration prometheus.Histogram
	CrowdSecPushErrors   prometheus.Counter
	CrowdSecQueueLength  prometheus.Gauge
	TrackedEntries       *prometheus.GaugeVec
	TrackedEvictions     *prometheus.CounterVec
	ProbeSuppressed      prometheus.Counter
	SessionsRejected     *prometheus.CounterVec
}

// SessionDurationBuckets cover short probes up to the longest session timeout (seconds).
var SessionDurationBuckets = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 120}

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
			Buckets: SessionDurationBuckets,
		}, []string{"protocol"}),
		CrowdSecPipeline: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_crowdsec_pipeline_total",
			Help: "Total number of CrowdSec alert pipeline events by stage (received, invalid, closed, filtered, cooldown, queued, dropped, sent, failed, released).",
		}, []string{"protocol", "stage"}),
		CrowdSecDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ran_crowdsec_alerts_dropped_total",
			Help: "Total number of CrowdSec alerts dropped due to full channel.",
		}, []string{"protocol"}),
	}

	m.PanicsRecovered = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ran_panics_recovered_total",
		Help: "Total number of panics recovered at connection and packet boundaries.",
	}, []string{"protocol"})

	m.ProxyDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ran_proxy_protocol_dropped_total",
		Help: "Total number of connections dropped by the PROXY protocol listener (no valid header, deadline, or handshake limit).",
	}, []string{"protocol"})

	m.UDPRateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ran_udp_rate_limited_total",
		Help: "Total number of UDP packets dropped by the packet rate limiter.",
	}, []string{"protocol"})

	m.IgnoredSessions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ran_ignored_sessions_total",
		Help: "Total number of sessions from sources in RAN_IGNORE_IPS (served and logged, never alerted).",
	}, []string{"protocol"})

	m.CrowdSecPushDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ran_crowdsec_push_duration_seconds",
		Help:    "Duration of CrowdSec LAPI alert push requests in seconds.",
		Buckets: prometheus.DefBuckets,
	})
	m.CrowdSecPushErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ran_crowdsec_push_errors_total",
		Help: "Total number of failed CrowdSec LAPI alert pushes (transport errors and non-2xx responses).",
	})
	m.CrowdSecQueueLength = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ran_crowdsec_queue_length",
		Help: "Number of alerts waiting in the CrowdSec send queue.",
	})
	m.TrackedEntries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ran_tracked_entries",
		Help: "Entries in the bounded tracking maps (map: scan, probe, cooldown).",
	}, []string{"map"})
	m.TrackedEvictions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ran_tracked_evictions_total",
		Help: "Live entries evicted from a tracking map because it was full (map: scan, probe, cooldown).",
	}, []string{"map"})
	m.ProbeSuppressed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ran_probe_summary_suppressed_sessions_total",
		Help: "Probe sessions whose per-session log lines were replaced by a probe summary.",
	})
	m.SessionsRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ran_sessions_rejected_total",
		Help: "Total number of TCP connections rejected by the session limiter.",
	}, []string{"protocol"})

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ran_build_info",
		Help: "Build information for ran.",
	}, []string{"version", "goversion"})
	buildInfo.WithLabelValues(version, runtime.Version()).Set(1)

	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(m.Connections, m.CredentialsCaptured, m.ActiveSessions, m.SessionDuration, m.CrowdSecPipeline, m.CrowdSecDropped, m.PanicsRecovered, m.ProxyDropped, m.UDPRateLimited, m.IgnoredSessions, m.CrowdSecPushDuration, m.CrowdSecPushErrors, m.CrowdSecQueueLength, m.TrackedEntries, m.TrackedEvictions, m.ProbeSuppressed, m.SessionsRejected, buildInfo)
	return m
}
