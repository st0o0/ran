package trap

import "sync"

type Limiter struct {
	maxGlobal int
	maxPerIP  int

	mu      sync.Mutex
	global  int
	perIP   map[string]int
}

func NewLimiter(maxGlobal, maxPerIP int) *Limiter {
	return &Limiter{
		maxGlobal: maxGlobal,
		maxPerIP:  maxPerIP,
		perIP:     make(map[string]int),
	}
}

func (l *Limiter) Acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global >= l.maxGlobal {
		return false
	}
	if l.perIP[ip] >= l.maxPerIP {
		return false
	}
	l.global++
	l.perIP[ip]++
	return true
}

func (l *Limiter) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global--
	l.perIP[ip]--
	if l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}
