package trap

import (
	"context"
	"net"
	"testing"
	"time"
)

type listeningTrap interface {
	Trap
	Ready() <-chan struct{}
	Addr() net.Addr
}

// serveTrap starts tr, waits until it listens and returns the bound address.
// The trap must be configured with port 0 (for example "127.0.0.1:0"), which
// removes the pick-a-port-then-reuse race and the startup sleep. The trap is
// stopped when the test ends.
func serveTrap(t testing.TB, ctx context.Context, tr Trap) string {
	t.Helper()
	lt, ok := tr.(listeningTrap)
	if !ok {
		t.Fatalf("%T does not report its listen address", tr)
	}
	errc := make(chan error, 1)
	go func() { errc <- tr.Start(ctx) }()

	select {
	case <-lt.Ready():
	case err := <-errc:
		t.Fatalf("trap start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("trap did not start listening")
	}

	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tr.Stop(stopCtx); err != nil {
			t.Errorf("trap stop: %v", err)
		}
		select {
		case err := <-errc:
			_ = err
		case <-time.After(5 * time.Second):
			t.Error("trap Start did not return after Stop")
		}
	})
	return lt.Addr().String()
}
