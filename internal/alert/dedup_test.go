package alert

import (
	"testing"
	"time"
)

func TestDedupAllowFirst(t *testing.T) {
	d := newDedupFilter(5*time.Minute, defaultMaxTracked)
	if !d.allowed("1.2.3.4|ssh") {
		t.Error("first call should be allowed")
	}
}

func TestDedupSuppressDuplicate(t *testing.T) {
	d := newDedupFilter(5*time.Minute, defaultMaxTracked)
	d.allowed("1.2.3.4|ssh")
	if d.allowed("1.2.3.4|ssh") {
		t.Error("duplicate within window should be suppressed")
	}
}

func TestDedupAllowAfterWindow(t *testing.T) {
	now := time.Now()
	d := newDedupFilter(5*time.Minute, defaultMaxTracked)
	d.nowFunc = func() time.Time { return now }

	d.allowed("1.2.3.4|ssh")

	d.nowFunc = func() time.Time { return now.Add(6 * time.Minute) }
	if !d.allowed("1.2.3.4|ssh") {
		t.Error("should allow after window expires")
	}
}

func TestDedupDifferentKeys(t *testing.T) {
	d := newDedupFilter(5*time.Minute, defaultMaxTracked)
	d.allowed("1.2.3.4|ssh")
	if !d.allowed("5.6.7.8|ssh") {
		t.Error("different IP should be allowed")
	}
	if !d.allowed("1.2.3.4|http") {
		t.Error("different protocol should be allowed")
	}
}

func TestDedupCleanup(t *testing.T) {
	now := time.Now()
	d := newDedupFilter(5*time.Minute, defaultMaxTracked)
	d.nowFunc = func() time.Time { return now }

	d.allowed("old|key")

	d.nowFunc = func() time.Time { return now.Add(11 * time.Minute) }
	d.allowed("new|key")
	d.cleanup()

	d.mu.Lock()
	_, oldExists := d.seen["old|key"]
	_, newExists := d.seen["new|key"]
	d.mu.Unlock()

	if oldExists {
		t.Error("old entry should have been cleaned up")
	}
	if !newExists {
		t.Error("new entry should still exist")
	}
}

func TestDedupDisabled(t *testing.T) {
	d := newDedupFilter(0, defaultMaxTracked)
	for range 100 {
		if !d.allowed("1.2.3.4|ssh") {
			t.Fatal("disabled dedup should always allow")
		}
	}
}

func TestDedupCleanupDisabled(t *testing.T) {
	d := newDedupFilter(0, defaultMaxTracked)
	d.cleanup()
}

// allowed is a test shorthand for Allow that ignores the slot.
func (d *dedupFilter) allowed(key string) bool {
	_, ok := d.Allow(key)
	return ok
}
