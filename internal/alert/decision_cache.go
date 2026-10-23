package alert

import (
	"container/list"
	"sync"
	"time"
)

type DecisionCache interface {
	IsBanned(ip string) bool
	MarkBanned(ip string, duration time.Duration)
}

var permanentBanExpiry = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

type banEntry struct {
	ip     string
	expiry time.Time
}

// localDecisionCache keeps bans in a FIFO list so that, when full, the oldest
// entry is evicted in O(1). Expired entries are swept by cleanup, off the hot path.
//
// Eviction trade-off: a flood of unique sources can evict an entry that is still
// inside its ban window, so a repeat alert for it may pass the cache. This is
// accepted: the LAPI stays authoritative and simply re-confirms the ban.
type localDecisionCache struct {
	mu         sync.RWMutex
	bans       map[string]*list.Element
	order      *list.List
	maxEntries int
	nowFunc    func() time.Time
}

func newLocalDecisionCache(maxEntries int) *localDecisionCache {
	return &localDecisionCache{
		bans:       make(map[string]*list.Element),
		order:      list.New(),
		maxEntries: maxEntries,
		nowFunc:    time.Now,
	}
}

func (c *localDecisionCache) IsBanned(ip string) bool {
	c.mu.RLock()
	el, ok := c.bans[ip]
	var expiry time.Time
	if ok {
		expiry = el.Value.(*banEntry).expiry
	}
	c.mu.RUnlock()
	if !ok {
		return false
	}
	now := c.nowFunc()
	if now.Before(expiry) {
		return true
	}
	c.mu.Lock()
	// Re-check: the ban may have been renewed in between.
	if el, ok := c.bans[ip]; ok && !now.Before(el.Value.(*banEntry).expiry) {
		c.remove(el)
	}
	c.mu.Unlock()
	return false
}

func (c *localDecisionCache) MarkBanned(ip string, duration time.Duration) {
	expiry := permanentBanExpiry
	if duration > 0 {
		expiry = c.nowFunc().Add(duration)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.bans[ip]; ok {
		// Keep the later expiry so a shorter ban never shortens a longer one.
		if e := el.Value.(*banEntry); expiry.After(e.expiry) {
			e.expiry = expiry
		}
		c.order.MoveToBack(el)
		return
	}
	if len(c.bans) >= c.maxEntries {
		// Full: evict the oldest entry; the LAPI stays authoritative.
		if front := c.order.Front(); front != nil {
			c.remove(front)
		}
	}
	c.bans[ip] = c.order.PushBack(&banEntry{ip: ip, expiry: expiry})
}

func (c *localDecisionCache) remove(el *list.Element) {
	delete(c.bans, el.Value.(*banEntry).ip)
	c.order.Remove(el)
}

func (c *localDecisionCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFunc()
	for el := c.order.Front(); el != nil; {
		next := el.Next()
		if now.After(el.Value.(*banEntry).expiry) {
			c.remove(el)
		}
		el = next
	}
}

type noopDecisionCache struct{}

func (noopDecisionCache) IsBanned(string) bool             { return false }
func (noopDecisionCache) MarkBanned(string, time.Duration) {}
