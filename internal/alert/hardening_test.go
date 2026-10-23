package alert

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/st0o0/ran/internal/metrics"
)

func pipelineCount(t *testing.T, m *metrics.Metrics, protocol, stage string) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.CrowdSecPipeline.WithLabelValues(protocol, stage).Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetCounter().GetValue()
}

// newTestAlerter builds an alerter without a LAPI connection; alerts stay in ch.
func newTestAlerter(t *testing.T, chSize int) *CrowdSecAlerter {
	t.Helper()
	return &CrowdSecAlerter{
		logger:        slog.Default(),
		metrics:       testMetrics(t),
		dedup:         newDedupFilter(time.Minute, 100),
		decisionCache: noopDecisionCache{},
		ch:            make(chan alertMsg, chSize),
	}
}

func TestAlertRejectsInvalidIPs(t *testing.T) {
	invalid := []string{
		"not-an-ip", "", "2001:db8::1%eth0", "8.8.8.8%eth0", "1.2.3.4:80", "999.1.1.1",
		// One representative (plus edge) per denied prefix.
		"0.0.0.0", "0.1.2.3", "10.0.0.5", "10.255.255.255",
		"100.64.0.1", "100.127.255.254", "127.0.0.1", "127.255.255.254",
		"169.254.1.1", "172.16.0.1", "172.31.255.254", "192.0.0.8", "192.0.2.10",
		"192.88.99.1", "192.168.1.1", "198.18.0.1", "198.19.255.254",
		"198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250",
		"240.0.0.1", "255.255.255.255",
		"::", "::1", "::2", "::a00:1", "64:ff9b::808:808", "100::1",
		"64:ff9b:1::1", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff", "2001::1", "2001:1ff:ffff::1", "3fff::1", "3fff:fff:ffff::1", "5f00::1", "5f00:ffff::1",
		"2001:db8::1", "2002:808:808::1", "fc00::1", "fd12:3456::1",
		"fe80::1", "febf::1", "ff02::1",
		// IPv4-mapped forms are unmapped first, then checked.
		"::ffff:10.0.0.5", "::ffff:127.0.0.1", "::ffff:100.64.0.1", "::ffff:192.0.2.10",
	}
	a := newTestAlerter(t, 64)
	for _, ip := range invalid {
		a.Alert(context.Background(), ip, "http", nil)
	}
	if len(a.ch) != 0 {
		t.Errorf("queued %d alerts for invalid IPs, want 0", len(a.ch))
	}
	if got := pipelineCount(t, a.metrics, "http", "invalid"); got != float64(len(invalid)) {
		t.Errorf("invalid stage = %v, want %d", got, len(invalid))
	}
	if len(a.dedup.seen) != 0 {
		t.Errorf("dedup map has %d entries, want 0", len(a.dedup.seen))
	}
}

func TestNonGlobalPrefixesAllDenied(t *testing.T) {
	// The first address of every denied prefix must be rejected.
	for _, p := range nonGlobalPrefixes {
		if _, ok := parseBannableIP(p.Addr().String()); ok {
			t.Errorf("first address of %s was accepted", p)
		}
	}
	if len(nonGlobalPrefixes) != 30 {
		t.Errorf("%d denied prefixes, want 30", len(nonGlobalPrefixes))
	}
}

func TestBannableIPsAccepted(t *testing.T) {
	for _, ip := range []string{
		"8.8.8.8", "1.1.1.1", "9.255.255.255", "11.0.0.1", "100.63.255.255", "100.128.0.1",
		"172.15.255.255", "172.32.0.1", "192.0.1.1", "192.0.3.1", "198.17.255.255",
		"198.20.0.1", "223.255.255.254", "2606:4700:4700::1111", "2001:4860:4860::8888",
		"2001:db9::1", "2001:200::1", "3fff:1000::1", "5f01::1", "64:ff9b:2::1", "2003::1", "2a00:1450::1",
	} {
		if _, ok := parseBannableIP(ip); !ok {
			t.Errorf("%s was rejected", ip)
		}
	}
}

func TestAlertAcceptsGlobalIPsAndUnmaps(t *testing.T) {
	a := newTestAlerter(t, 16)
	a.Alert(context.Background(), "::ffff:8.8.8.8", "http", nil)
	a.Alert(context.Background(), "2606:4700:4700::1111", "http", nil)

	if len(a.ch) != 2 {
		t.Fatalf("queued %d alerts, want 2", len(a.ch))
	}
	if msg := <-a.ch; msg.IP != "8.8.8.8" {
		t.Errorf("IP = %q, want unmapped 8.8.8.8", msg.IP)
	}
	if msg := <-a.ch; msg.IP != "2606:4700:4700::1111" {
		t.Errorf("IP = %q, want 2606:4700:4700::1111", msg.IP)
	}
}

func TestDedupMappedAndPlainFormShareSlot(t *testing.T) {
	a := newTestAlerter(t, 16)
	a.Alert(context.Background(), "::ffff:8.8.8.8", "http", nil)
	a.Alert(context.Background(), "8.8.8.8", "http", nil)
	if len(a.ch) != 1 {
		t.Errorf("queued %d alerts, want 1", len(a.ch))
	}
}

func TestDroppedAlertReleasesDedupSlot(t *testing.T) {
	a := newTestAlerter(t, 1)
	ctx := context.Background()

	a.Alert(ctx, "8.8.8.8", "http", nil) // fills the channel
	a.Alert(ctx, "1.1.1.1", "http", nil) // dropped
	if got := pipelineCount(t, a.metrics, "http", "dropped"); got != 1 {
		t.Fatalf("dropped = %v, want 1", got)
	}

	<-a.ch // make space
	a.Alert(ctx, "1.1.1.1", "http", nil)
	if len(a.ch) != 1 {
		t.Fatalf("retry of dropped alert was suppressed (queued %d)", len(a.ch))
	}
	if got := pipelineCount(t, a.metrics, "http", "deduplicated"); got != 0 {
		t.Errorf("deduplicated = %v, want 0", got)
	}
}

func TestDedupReleaseKeepsNewerSlot(t *testing.T) {
	now := time.Now()
	d := newDedupFilter(time.Minute, 10)
	d.nowFunc = func() time.Time { return now }

	oldSlot, ok := d.Allow("k")
	if !ok {
		t.Fatal("first Allow denied")
	}
	// The window passes and another alert re-arms the key before the first
	// one gives up its (expired) slot.
	now = now.Add(2 * time.Minute)
	newSlot, ok := d.Allow("k")
	if !ok {
		t.Fatal("re-arm denied")
	}
	d.Release("k", oldSlot)
	if d.allowed("k") {
		t.Error("stale Release deleted the newer slot")
	}
	d.Release("k", newSlot)
	if !d.allowed("k") {
		t.Error("Release with the current slot should free the key")
	}
}

func TestDedupFloodIsFast(t *testing.T) {
	now := time.Now()
	d := newDedupFilter(time.Hour, 1000)
	d.nowFunc = func() time.Time { return now }

	start := time.Now()
	for i := 0; i < 200000; i++ {
		now = now.Add(time.Microsecond)
		d.Allow("key" + strconv.Itoa(i))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("200000 unique inserts took %v, want well under 2s", elapsed)
	}
	if len(d.seen) != 1000 || d.order.Len() != 1000 {
		t.Errorf("size = %d/%d, want 1000", len(d.seen), d.order.Len())
	}
}

func TestDecisionCacheFloodIsFast(t *testing.T) {
	now := time.Now()
	c := newLocalDecisionCache(1000)
	c.nowFunc = func() time.Time { return now }

	start := time.Now()
	for i := 0; i < 200000; i++ {
		c.MarkBanned("ip"+strconv.Itoa(i), time.Hour)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("200000 unique inserts took %v, want well under 2s", elapsed)
	}
	if len(c.bans) != 1000 || c.order.Len() != 1000 {
		t.Errorf("size = %d/%d, want 1000", len(c.bans), c.order.Len())
	}
}

func TestDedupConcurrentAllowReleaseAlert(t *testing.T) {
	a := newTestAlerter(t, 8)
	a.dedup = newDedupFilter(time.Minute, 64)
	a.decisionCache = newLocalDecisionCache(64)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				key := "k" + strconv.Itoa((g*7+i)%200)
				if slot, ok := a.dedup.Allow(key); ok && i%3 == 0 {
					a.dedup.Release(key, slot)
				}
				a.decisionCache.MarkBanned("ip"+strconv.Itoa(i%200), time.Minute)
				a.decisionCache.IsBanned("ip" + strconv.Itoa(i%200))
				a.Alert(context.Background(), "8.8."+strconv.Itoa(g)+"."+strconv.Itoa(i%250), "http", nil)
				if i%100 == 0 {
					a.dedup.cleanup()
					a.decisionCache.(*localDecisionCache).cleanup()
				}
				select {
				case <-a.ch:
				default:
				}
			}
		}(g)
	}
	wg.Wait()

	if len(a.dedup.seen) > 64 || a.dedup.order.Len() != len(a.dedup.seen) {
		t.Errorf("dedup size %d / list %d breaks the cap invariant", len(a.dedup.seen), a.dedup.order.Len())
	}
}

func TestCloseIsIdempotentAndAlertAfterCloseIsSafe(t *testing.T) {
	a := newTestAlerter(t, 4)
	a.stopCh = make(chan struct{})
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				a.Alert(context.Background(), "8.8."+strconv.Itoa(g)+"."+strconv.Itoa(i%250), "http", nil)
			}
		}(g)
	}
	a.Close()
	a.Close() // second Close must not panic
	wg.Wait()
	before := pipelineCount(t, a.metrics, "http", "closed")
	a.Alert(context.Background(), "1.1.1.1", "http", nil) // after Close: dropped and counted
	if got := pipelineCount(t, a.metrics, "http", "closed"); got != before+1 {
		t.Errorf("closed stage = %v, want %v", got, before+1)
	}
}

func TestDecisionCacheCapped(t *testing.T) {
	c := newLocalDecisionCache(5)
	for i := 0; i < 50; i++ {
		c.MarkBanned("198.20.0."+strconv.Itoa(i), time.Hour)
		if len(c.bans) > 5 || c.order.Len() != len(c.bans) {
			t.Fatalf("size %d (list %d) breaks cap 5", len(c.bans), c.order.Len())
		}
	}
	// The oldest entries are evicted first, the newest stay cached.
	if c.IsBanned("198.20.0.0") {
		t.Error("oldest entry should have been evicted")
	}
	if !c.IsBanned("198.20.0.49") {
		t.Error("newest entry should be cached")
	}
}

func TestDecisionCacheCleanupRemovesExpired(t *testing.T) {
	now := time.Now()
	c := newLocalDecisionCache(10)
	c.nowFunc = func() time.Time { return now }
	c.MarkBanned("198.20.0.1", time.Minute)
	c.MarkBanned("198.20.0.2", time.Hour)
	now = now.Add(2 * time.Minute)
	c.cleanup()
	if len(c.bans) != 1 || c.order.Len() != 1 {
		t.Errorf("size = %d/%d, want 1 after cleanup", len(c.bans), c.order.Len())
	}
	if !c.IsBanned("198.20.0.2") {
		t.Error("live ban should survive cleanup")
	}
}

func TestDedupCapped(t *testing.T) {
	d := newDedupFilter(time.Hour, 5)
	for i := 0; i < 50; i++ {
		if !d.allowed("key" + strconv.Itoa(i)) {
			t.Fatalf("key%d unexpectedly denied", i)
		}
		if len(d.seen) > 5 {
			t.Fatalf("map size %d exceeds cap 5", len(d.seen))
		}
	}
}

func TestDedupEvictsOldestWhenFull(t *testing.T) {
	now := time.Now()
	d := newDedupFilter(time.Hour, 3)
	d.nowFunc = func() time.Time { return now }
	for _, k := range []string{"a", "b", "c"} {
		now = now.Add(time.Second)
		d.allowed(k)
	}
	now = now.Add(time.Second)
	d.allowed("d")
	if _, ok := d.seen["a"]; ok {
		t.Error("oldest entry a should have been evicted")
	}
	if len(d.seen) != 3 {
		t.Errorf("size = %d, want 3", len(d.seen))
	}
}

func TestDedupSweepsExpiredBeforeEvicting(t *testing.T) {
	now := time.Now()
	d := newDedupFilter(time.Minute, 2)
	d.nowFunc = func() time.Time { return now }
	d.allowed("a")
	d.allowed("b")
	now = now.Add(2 * time.Minute)
	d.allowed("c")
	if len(d.seen) != 1 {
		t.Errorf("size = %d, want 1 after sweeping expired entries", len(d.seen))
	}
}

func TestDecisionCacheSweepsExpiredWhenFull(t *testing.T) {
	now := time.Now()
	c := newLocalDecisionCache(2)
	c.nowFunc = func() time.Time { return now }
	c.MarkBanned("192.0.2.1", time.Minute)
	c.MarkBanned("192.0.2.2", time.Minute)
	now = now.Add(2 * time.Minute)
	c.MarkBanned("192.0.2.3", time.Minute)
	if !c.IsBanned("192.0.2.3") {
		t.Error("new entry should be cached after sweeping expired ones")
	}
}

func TestBuildEventMetaDropsPassword(t *testing.T) {
	out := buildEventMeta(map[string]string{"username": "root", "password": "hunter2", "path": "/x"})
	if len(out) != 2 {
		t.Fatalf("got %d entries, want 2", len(out))
	}
	for _, m := range out {
		if m.Key == "password" {
			t.Error("password must not be sent to CrowdSec")
		}
	}
}

func TestDecisionCacheMarkBannedKeepsMaxExpiry(t *testing.T) {
	now := time.Now()
	c := newLocalDecisionCache(10)
	c.nowFunc = func() time.Time { return now }

	c.MarkBanned("8.8.8.8", 4*time.Hour)
	c.MarkBanned("8.8.8.8", time.Minute) // shorter ban must not shorten the cached expiry
	c.nowFunc = func() time.Time { return now.Add(time.Hour) }
	if !c.IsBanned("8.8.8.8") {
		t.Error("shorter re-mark shortened the ban")
	}

	c.nowFunc = func() time.Time { return now }
	c.MarkBanned("1.1.1.1", time.Minute)
	c.MarkBanned("1.1.1.1", 4*time.Hour) // longer ban extends it
	c.nowFunc = func() time.Time { return now.Add(time.Hour) }
	if !c.IsBanned("1.1.1.1") {
		t.Error("longer re-mark did not extend the ban")
	}

	c.nowFunc = func() time.Time { return now }
	c.MarkBanned("9.9.9.9", 0) // permanent
	c.MarkBanned("9.9.9.9", time.Minute)
	c.nowFunc = func() time.Time { return now.Add(24 * time.Hour) }
	if !c.IsBanned("9.9.9.9") {
		t.Error("finite re-mark downgraded a permanent ban")
	}
}
