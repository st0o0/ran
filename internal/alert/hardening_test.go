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

func droppedCount(t *testing.T, m *metrics.Metrics, protocol string) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.CrowdSecDropped.WithLabelValues(protocol).Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.GetCounter().GetValue()
}

// newTestAlerter builds an alerter without a LAPI connection; alerts stay in ch.
func newTestAlerter(t *testing.T, chSize int) *CrowdSecAlerter {
	t.Helper()
	return &CrowdSecAlerter{
		logger:   slog.Default(),
		metrics:  testMetrics(t),
		banOn:    map[Class]bool{ClassProbe: true, ClassAttack: true, ClassScan: true},
		cooldown: newCooldownFilter(time.Minute, 100),
		ch:       make(chan alertMsg, chSize),
	}
}

func TestSubmitRejectsInvalidIPs(t *testing.T) {
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
		a.Submit(context.Background(), evClass(ip, "http", ClassAttack))
	}
	if len(a.ch) != 0 {
		t.Errorf("queued %d alerts for invalid IPs, want 0", len(a.ch))
	}
	if got := pipelineCount(t, a.metrics, "http", "invalid"); got != float64(len(invalid)) {
		t.Errorf("invalid stage = %v, want %d", got, len(invalid))
	}
	if len(a.cooldown.seen) != 0 {
		t.Errorf("cooldown map has %d entries, want 0", len(a.cooldown.seen))
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

func TestSubmitAcceptsGlobalIPsAndUnmaps(t *testing.T) {
	a := newTestAlerter(t, 16)
	a.Submit(context.Background(), ev("::ffff:8.8.8.8", "http"))
	a.Submit(context.Background(), ev("2606:4700:4700::1111", "http"))

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

func TestCooldownMappedAndPlainFormShareSlot(t *testing.T) {
	a := newTestAlerter(t, 16)
	a.Submit(context.Background(), ev("::ffff:8.8.8.8", "http"))
	a.Submit(context.Background(), ev("8.8.8.8", "http"))
	if len(a.ch) != 1 {
		t.Errorf("queued %d alerts, want 1", len(a.ch))
	}
}

func TestDroppedAlertReleasesCooldownSlot(t *testing.T) {
	a := newTestAlerter(t, 1)
	ctx := context.Background()

	a.Submit(ctx, ev("8.8.8.8", "http")) // fills the channel
	a.Submit(ctx, ev("1.1.1.1", "http")) // dropped
	if got := pipelineCount(t, a.metrics, "http", "dropped"); got != 1 {
		t.Fatalf("dropped = %v, want 1", got)
	}

	<-a.ch // make space
	a.Submit(ctx, ev("1.1.1.1", "http"))
	if len(a.ch) != 1 {
		t.Fatalf("retry of dropped alert was suppressed (queued %d)", len(a.ch))
	}
	if got := pipelineCount(t, a.metrics, "http", "cooldown"); got != 0 {
		t.Errorf("cooldown = %v, want 0", got)
	}
}

func TestCooldownReleaseKeepsNewerSlot(t *testing.T) {
	now := time.Now()
	d := newCooldownFilter(time.Minute, 10)
	d.nowFunc = func() time.Time { return now }

	oldKey, oldSlot, ok := d.Allow("8.8.8.8", ClassAttack)
	if !ok {
		t.Fatal("first Allow denied")
	}
	// The window passes and another alert re-arms the key before the first
	// one gives up its (expired) slot.
	now = now.Add(2 * time.Minute)
	newKey, newSlot, ok := d.Allow("8.8.8.8", ClassAttack)
	if !ok {
		t.Fatal("re-arm denied")
	}
	d.Release(oldKey, oldSlot)
	if _, _, ok := d.Allow("8.8.8.8", ClassAttack); ok {
		t.Error("stale Release deleted the newer slot")
	}
	d.Release(newKey, newSlot)
	if _, _, ok := d.Allow("8.8.8.8", ClassAttack); !ok {
		t.Error("Release with the current slot should free the key")
	}
}

func TestCooldownWindowExpiry(t *testing.T) {
	now := time.Now()
	d := newCooldownFilter(time.Hour, 10)
	d.nowFunc = func() time.Time { return now }
	if _, _, ok := d.Allow("8.8.8.8", ClassAttack); !ok {
		t.Fatal("first denied")
	}
	now = now.Add(59 * time.Minute)
	if _, _, ok := d.Allow("8.8.8.8", ClassAttack); ok {
		t.Error("allowed inside the window")
	}
	now = now.Add(2 * time.Minute)
	if _, _, ok := d.Allow("8.8.8.8", ClassAttack); !ok {
		t.Error("denied after the window")
	}
}

func TestCooldownDisabled(t *testing.T) {
	d := newCooldownFilter(0, 10)
	for range 5 {
		if _, _, ok := d.Allow("8.8.8.8", ClassAttack); !ok {
			t.Fatal("window 0 must allow everything")
		}
	}
	d.cleanup() // must not panic
}

func TestCooldownClassRules(t *testing.T) {
	now := time.Now()
	d := newCooldownFilter(time.Hour, 10)
	d.nowFunc = func() time.Time { return now }
	ip := "8.8.8.8"
	steps := []struct {
		class Class
		want  bool
	}{
		{ClassProbe, true},
		{ClassProbe, false},
		{ClassAttack, true},  // escalation bypass
		{ClassProbe, false},  // lower class while higher is cooling down
		{ClassAttack, false}, // same class
		{ClassScan, true},    // escalation bypass
		{ClassAttack, false}, // lower class
		{ClassScan, false},
	}
	for i, s := range steps {
		if _, _, ok := d.Allow(ip, s.class); ok != s.want {
			t.Errorf("step %d (%s): allowed = %v, want %v", i, s.class, ok, s.want)
		}
	}
	// A different IP is independent.
	if _, _, ok := d.Allow("1.1.1.1", ClassProbe); !ok {
		t.Error("other IP denied")
	}
}

func TestCooldownFloodIsFast(t *testing.T) {
	now := time.Now()
	d := newCooldownFilter(time.Hour, 1000)
	d.nowFunc = func() time.Time { return now }

	start := time.Now()
	for i := 0; i < 200000; i++ {
		now = now.Add(time.Microsecond)
		d.Allow("ip"+strconv.Itoa(i), ClassAttack)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("200000 unique inserts took %v, want well under 2s", elapsed)
	}
	if len(d.seen) != 1000 || d.order.Len() != 1000 {
		t.Errorf("size = %d/%d, want 1000", len(d.seen), d.order.Len())
	}
}

func TestCooldownConcurrentAllowReleaseSubmit(t *testing.T) {
	a := newTestAlerter(t, 8)
	a.cooldown = newCooldownFilter(time.Minute, 64)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				ip := "8.8." + strconv.Itoa(g) + "." + strconv.Itoa(i%200)
				if key, slot, ok := a.cooldown.Allow(ip, ClassAttack); ok && i%3 == 0 {
					a.cooldown.Release(key, slot)
				}
				a.Submit(context.Background(), ev("8.9."+strconv.Itoa(g)+"."+strconv.Itoa(i%250), "http"))
				if i%100 == 0 {
					a.cooldown.cleanup()
				}
				select {
				case <-a.ch:
				default:
				}
			}
		}(g)
	}
	wg.Wait()

	if len(a.cooldown.seen) > 64 || a.cooldown.order.Len() != len(a.cooldown.seen) {
		t.Errorf("cooldown size %d / list %d breaks the cap invariant", len(a.cooldown.seen), a.cooldown.order.Len())
	}
}

func TestCloseIsIdempotentAndSubmitAfterCloseIsSafe(t *testing.T) {
	a := newTestAlerter(t, 4)
	a.stopCh = make(chan struct{})
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				a.Submit(context.Background(), ev("8.8."+strconv.Itoa(g)+"."+strconv.Itoa(i%250), "http"))
			}
		}(g)
	}
	a.Close()
	a.Close() // second Close must not panic
	wg.Wait()
	before := pipelineCount(t, a.metrics, "http", "closed")
	a.Submit(context.Background(), ev("1.1.1.1", "http")) // after Close: dropped and counted
	if got := pipelineCount(t, a.metrics, "http", "closed"); got != before+1 {
		t.Errorf("closed stage = %v, want %v", got, before+1)
	}
}

func TestCooldownCapped(t *testing.T) {
	d := newCooldownFilter(time.Hour, 5)
	for i := 0; i < 50; i++ {
		if _, _, ok := d.Allow("198.20.0."+strconv.Itoa(i), ClassAttack); !ok {
			t.Fatalf("ip %d unexpectedly denied", i)
		}
		if len(d.seen) > 5 {
			t.Fatalf("map size %d exceeds cap 5", len(d.seen))
		}
	}
}

func TestCooldownEvictsOldestWhenFull(t *testing.T) {
	now := time.Now()
	d := newCooldownFilter(time.Hour, 3)
	d.nowFunc = func() time.Time { return now }
	for _, ip := range []string{testIP(1), testIP(2), testIP(3)} {
		now = now.Add(time.Second)
		d.Allow(ip, ClassAttack)
	}
	now = now.Add(time.Second)
	d.Allow(testIP(4), ClassAttack)
	if _, ok := d.seen[cooldownKey(testIP(1), ClassAttack)]; ok {
		t.Error("oldest entry should have been evicted")
	}
	if len(d.seen) != 3 {
		t.Errorf("size = %d, want 3", len(d.seen))
	}
}

func TestCooldownSweepsExpiredBeforeEvicting(t *testing.T) {
	now := time.Now()
	d := newCooldownFilter(time.Minute, 2)
	d.nowFunc = func() time.Time { return now }
	d.Allow(testIP(1), ClassAttack)
	d.Allow(testIP(2), ClassAttack)
	now = now.Add(2 * time.Minute)
	d.Allow(testIP(3), ClassAttack)
	if len(d.seen) != 1 {
		t.Errorf("size = %d, want 1 after sweeping expired entries", len(d.seen))
	}
}

func TestCooldownCleanupRemovesExpired(t *testing.T) {
	now := time.Now()
	d := newCooldownFilter(time.Minute, 10)
	d.nowFunc = func() time.Time { return now }
	d.Allow(testIP(1), ClassAttack)
	now = now.Add(30 * time.Second)
	d.Allow(testIP(2), ClassAttack)
	now = now.Add(45 * time.Second)
	d.cleanup()
	if len(d.seen) != 1 || d.order.Len() != 1 {
		t.Errorf("size = %d/%d, want 1 after cleanup", len(d.seen), d.order.Len())
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

func TestEventMetaSensorKeysWin(t *testing.T) {
	meta := eventMeta(Event{
		Class: ClassAttack,
		Info:  SessionInfo{Protocol: "ssh", DestPort: 22, AuthAttempts: 3},
		Meta:  map[string]string{"class": "probe", "protocol": "evil", "auth_attempts": "0", "username": "root"},
	})
	if meta["class"] != "attack" || meta["protocol"] != "ssh" || meta["auth_attempts"] != "3" {
		t.Errorf("trap meta overrode sensor keys: %v", meta)
	}
	if meta["username"] != "root" {
		t.Errorf("trap meta lost: %v", meta)
	}
}
