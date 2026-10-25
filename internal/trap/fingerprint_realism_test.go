package trap

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/fingerprint"
	"github.com/st0o0/ran/internal/metrics"
)

func esProfile(version string, build fingerprint.ESBuild) *fingerprint.Profile {
	p := *fingerprint.Fixed()
	p.Mode = fingerprint.ModeSeeded
	p.Elasticsearch.Version = version
	p.Elasticsearch.Build = build
	return &p
}

func TestElasticsearchProductHeaderFollowsTheVersion(t *testing.T) {
	t.Parallel()
	build := fingerprint.ESBuild{Type: "docker", Hash: strings.Repeat("a", 40), Date: "2021-01-13T00:42:12.435326Z", Lucene: "8.7.0", MinWire: "6.8.0", MinIndex: "6.0.0-beta1"}
	for _, c := range []struct {
		version string
		header  bool
	}{{"7.10.2", false}, {"7.13.4", false}, {"7.14.0", true}, {"7.17.18", true}, {"8.11.4", true}} {
		addr := startProfileTrap(t, "elasticsearch", esProfile(c.version, build), func(cfg *config.Config) Trap {
			return NewElasticsearch(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
		})
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Version map[string]any `json:"version"`
			Tagline string         `json:"tagline"`
		}
		err = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.Header.Get("X-elastic-product") != ""; got != c.header {
			t.Errorf("%s: X-elastic-product present = %v, want %v", c.version, got, c.header)
		}
		for k, want := range map[string]any{
			"number": c.version, "build_flavor": "default", "build_type": "docker", "build_hash": build.Hash,
			"build_date": build.Date, "build_snapshot": false, "lucene_version": "8.7.0",
			"minimum_wire_compatibility_version": "6.8.0", "minimum_index_compatibility_version": "6.0.0-beta1",
		} {
			if doc.Version[k] != want {
				t.Errorf("%s: version.%s = %v, want %v", c.version, k, doc.Version[k], want)
			}
		}
		if doc.Tagline != "You Know, for Search" {
			t.Errorf("tagline = %q", doc.Tagline)
		}
	}
}

func TestEverySeededElasticsearchReleaseIsComplete(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := range 400 {
		p := fingerprint.FromSeed([]byte{byte(i), byte(i >> 8), 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		es := p.Elasticsearch
		b := es.Build
		if b.IsZero() || b.Type == "" || len(b.Hash) != 40 || b.Date == "" || b.Lucene == "" || b.MinWire == "" || b.MinIndex == "" {
			t.Fatalf("%s: incomplete build info %+v", es.Version, b)
		}
		seen[es.Version] = true
	}
	if len(seen) < 6 {
		t.Errorf("only %d versions seen", len(seen))
	}
}

func TestHTTPProfilesCarryKernelAndPackageVersion(t *testing.T) {
	t.Parallel()
	for i := range 256 {
		p := fingerprint.FromSeed([]byte{byte(i), 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
		h := p.HTTP
		if h.Kernel == "" || !strings.HasPrefix(h.PHPPackage, h.PHP+"-") {
			t.Fatalf("entry %+v: kernel or package version missing or inconsistent", h)
		}
		switch {
		case strings.Contains(h.PHPPackage, "24.04") && !strings.HasPrefix(h.Kernel, "6.8."),
			strings.Contains(h.PHPPackage, "ubuntu2") && !strings.HasPrefix(h.Kernel, "5.15."),
			strings.Contains(h.PHPPackage, "deb12") && !strings.HasPrefix(h.Kernel, "6.1."):
			t.Fatalf("entry %+v: kernel does not match the distribution", h)
		}
	}

	// phpinfo prints the package version and the kernel; X-Powered-By stays plain.
	p := fingerprint.FromSeed(make([]byte, fingerprint.SeedSize))
	addr := startProfileTrap(t, "http", p, func(cfg *config.Config) Trap {
		return NewHTTP(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
	})
	got := fxDo(t, false, addr, "GET", "/phpinfo.php", nil, "")
	if !strings.Contains(got.body, "PHP Version "+p.HTTP.PHPPackage) || !strings.Contains(got.body, "Linux webapp "+p.HTTP.Kernel+" x86_64") {
		t.Errorf("phpinfo = %q", got.body)
	}
	if got.header.Get("X-Powered-By") != "PHP/"+p.HTTP.PHP {
		t.Errorf("X-Powered-By = %q", got.header.Get("X-Powered-By"))
	}
}

func TestFixedPhpinfoKeepsTheOldValues(t *testing.T) {
	t.Parallel()
	addr := startProfileTrap(t, "http", fingerprint.Fixed(), func(cfg *config.Config) Trap {
		return NewHTTP(cfg, quietLogger(), metrics.New(prometheus.NewRegistry(), "test"), NewLimiter(100, 10), alert.NoopAlerter{})
	})
	got := fxDo(t, false, addr, "GET", "/phpinfo.php", nil, "")
	if !strings.Contains(got.body, "PHP Version 8.3.6</h1>") || !strings.Contains(got.body, "Linux webapp 5.15.0-91-generic x86_64 </td>") {
		t.Errorf("fixed phpinfo changed: %q", got.body)
	}
}
