package alert

import (
	"sync"
	"time"
)

type DecisionCache interface {
	IsBanned(ip string) bool
	MarkBanned(ip string, duration time.Duration)
}

var permanentBanExpiry = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

type localDecisionCache struct {
	mu      sync.RWMutex
	bans    map[string]time.Time
	nowFunc func() time.Time
}

func newLocalDecisionCache() *localDecisionCache {
	return &localDecisionCache{
		bans:    make(map[string]time.Time),
		nowFunc: time.Now,
	}
}

func (c *localDecisionCache) IsBanned(ip string) bool {
	c.mu.RLock()
	expiry, ok := c.bans[ip]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	if c.nowFunc().Before(expiry) {
		return true
	}
	c.mu.Lock()
	delete(c.bans, ip)
	c.mu.Unlock()
	return false
}

func (c *localDecisionCache) MarkBanned(ip string, duration time.Duration) {
	expiry := permanentBanExpiry
	if duration > 0 {
		expiry = c.nowFunc().Add(duration)
	}
	c.mu.Lock()
	c.bans[ip] = expiry
	c.mu.Unlock()
}

func (c *localDecisionCache) cleanup() {
	now := c.nowFunc()
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip, expiry := range c.bans {
		if now.After(expiry) {
			delete(c.bans, ip)
		}
	}
}

type noopDecisionCache struct{}

func (noopDecisionCache) IsBanned(string) bool               { return false }
func (noopDecisionCache) MarkBanned(string, time.Duration)   {}
