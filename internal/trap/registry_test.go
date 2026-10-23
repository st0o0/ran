package trap

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// The three trap name sets must never drift apart: a trap without a default
// port, an unlisted factory or a valid name without a factory all break startup.
func TestTrapKeySetsMatch(t *testing.T) {
	keys := func(n int, each func(func(string))) []string {
		out := make([]string, 0, n)
		each(func(k string) { out = append(out, k) })
		sort.Strings(out)
		return out
	}
	ports := keys(len(config.DefaultPorts), func(f func(string)) {
		for k := range config.DefaultPorts {
			f(k)
		}
	})
	valid := keys(len(config.ValidTraps), func(f func(string)) {
		for k := range config.ValidTraps {
			f(k)
		}
	})
	reg := keys(len(Registry), func(f func(string)) {
		for k := range Registry {
			f(k)
		}
	})
	same := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	if !same(ports, valid) {
		t.Errorf("DefaultPorts %v != ValidTraps %v", ports, valid)
	}
	if !same(ports, reg) {
		t.Errorf("DefaultPorts %v != Registry %v", ports, reg)
	}
}

func TestLogRejectedCountsMetric(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(), "test")
	LogRejected(slog.New(slog.NewJSONHandler(io.Discard, nil)), m, "ssh", alert.TransportTCP, 22, "8.8.8.8", "rate_limit")
	LogRejected(slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, "ssh", alert.TransportTCP, 22, "8.8.8.8", "rate_limit")

	var out dto.Metric
	if err := m.SessionsRejected.WithLabelValues("ssh").Write(&out); err != nil {
		t.Fatal(err)
	}
	if got := out.GetCounter().GetValue(); got != 1 {
		t.Errorf("rejected = %v, want 1", got)
	}
}

func TestSetOutcome(t *testing.T) {
	sess := NewSession("ftp", alert.TransportTCP, "8.8.8.8", 1, 21, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	cases := []struct {
		err  error
		want string
	}{
		{os.ErrDeadlineExceeded, "timeout"},
		{bufio.ErrTooLong, "too_long"},
		{io.EOF, "error"},
	}
	for _, c := range cases {
		setOutcome(sess, c.err)
		if sess.Outcome != c.want {
			t.Errorf("setOutcome(%v) = %q, want %q", c.err, sess.Outcome, c.want)
		}
	}
	if !isTimeout(os.ErrDeadlineExceeded) || isTimeout(io.EOF) {
		t.Error("isTimeout misclassified")
	}
}
