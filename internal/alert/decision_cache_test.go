package alert

import (
	"testing"
	"time"
)

func TestLocalCacheMarkAndCheck(t *testing.T) {
	c := newLocalDecisionCache()
	c.MarkBanned("1.2.3.4", 4*time.Hour)
	if !c.IsBanned("1.2.3.4") {
		t.Error("expected IP to be banned")
	}
}

func TestLocalCacheNotBanned(t *testing.T) {
	c := newLocalDecisionCache()
	if c.IsBanned("1.2.3.4") {
		t.Error("expected unknown IP to not be banned")
	}
}

func TestLocalCacheExpiry(t *testing.T) {
	now := time.Now()
	c := newLocalDecisionCache()
	c.nowFunc = func() time.Time { return now }

	c.MarkBanned("1.2.3.4", 1*time.Hour)

	c.nowFunc = func() time.Time { return now.Add(2 * time.Hour) }
	if c.IsBanned("1.2.3.4") {
		t.Error("expected ban to have expired")
	}
}

func TestLocalCachePermanentBan(t *testing.T) {
	now := time.Now()
	c := newLocalDecisionCache()
	c.nowFunc = func() time.Time { return now }

	c.MarkBanned("1.2.3.4", 0)

	c.nowFunc = func() time.Time { return now.Add(365 * 24 * time.Hour) }
	if !c.IsBanned("1.2.3.4") {
		t.Error("permanent ban should not expire")
	}
}

func TestLocalCacheCleanup(t *testing.T) {
	now := time.Now()
	c := newLocalDecisionCache()
	c.nowFunc = func() time.Time { return now }

	c.MarkBanned("expired", 1*time.Hour)
	c.MarkBanned("active", 4*time.Hour)

	c.nowFunc = func() time.Time { return now.Add(2 * time.Hour) }
	c.cleanup()

	c.mu.RLock()
	_, expiredExists := c.bans["expired"]
	_, activeExists := c.bans["active"]
	c.mu.RUnlock()

	if expiredExists {
		t.Error("expired entry should have been cleaned up")
	}
	if !activeExists {
		t.Error("active entry should still exist")
	}
}

func TestNoopDecisionCache(t *testing.T) {
	var c DecisionCache = noopDecisionCache{}
	c.MarkBanned("1.2.3.4", 4*time.Hour)
	if c.IsBanned("1.2.3.4") {
		t.Error("noop cache should never report banned")
	}
}
