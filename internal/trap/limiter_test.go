package trap

import (
	"sync"
	"testing"
)

func TestLimiterGlobal(t *testing.T) {
	l := NewLimiter(3, 10)
	for i := range 3 {
		if !l.Acquire("1.1.1." + string(rune('1'+i))) {
			t.Fatalf("acquire %d should succeed", i)
		}
	}
	if l.Acquire("2.2.2.2") {
		t.Fatal("acquire should fail at global limit")
	}
	l.Release("1.1.1.1")
	if !l.Acquire("2.2.2.2") {
		t.Fatal("acquire should succeed after release")
	}
}

func TestLimiterPerIP(t *testing.T) {
	l := NewLimiter(100, 2)
	if !l.Acquire("1.2.3.4") {
		t.Fatal("first acquire should succeed")
	}
	if !l.Acquire("1.2.3.4") {
		t.Fatal("second acquire should succeed")
	}
	if l.Acquire("1.2.3.4") {
		t.Fatal("third acquire from same IP should fail")
	}
	if !l.Acquire("5.6.7.8") {
		t.Fatal("different IP should succeed")
	}
}

func TestLimiterRelease(t *testing.T) {
	l := NewLimiter(100, 1)
	l.Acquire("1.2.3.4")
	l.Release("1.2.3.4")
	if !l.Acquire("1.2.3.4") {
		t.Fatal("acquire after release should succeed")
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter(100, 100)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Acquire("1.1.1.1") {
				l.Release("1.1.1.1")
			}
		}()
	}
	wg.Wait()
}
