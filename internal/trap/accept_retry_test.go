package trap

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/config"
)

type acceptResult struct {
	conn net.Conn
	err  error
}

// scriptedListener returns the scripted results in order, then blocks until
// Close and returns net.ErrClosed.
type scriptedListener struct {
	mu      sync.Mutex
	results []acceptResult
	closed  chan struct{}
	once    sync.Once
}

func newScriptedListener(results ...acceptResult) *scriptedListener {
	return &scriptedListener{results: results, closed: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.results) > 0 {
		r := l.results[0]
		l.results = l.results[1:]
		l.mu.Unlock()
		return r.conn, r.err
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

func fastAcceptBackoff(t *testing.T) {
	t.Helper()
	oldMin, oldMax := acceptPanicBackoffMin, acceptPanicBackoffMax
	acceptPanicBackoffMin, acceptPanicBackoffMax = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { acceptPanicBackoffMin, acceptPanicBackoffMax = oldMin, oldMax })
}

func TestMultiListenerSurvivesTransientAcceptErrors(t *testing.T) {
	fastAcceptBackoff(t)
	server, client := net.Pipe()
	defer client.Close()
	emfile := errors.New("accept tcp: too many open files")
	ln := newScriptedListener(
		acceptResult{err: emfile},
		acceptResult{err: emfile},
		acceptResult{err: emfile},
		acceptResult{conn: server},
	)
	logs := &syncBuffer{}
	ml := newMultiListener([]net.Listener{ln}, newJSONLogger(logs), nil, "ssh")
	defer ml.Close()

	got := make(chan net.Conn, 1)
	go func() {
		c, err := ml.Accept()
		if err == nil {
			got <- c
		}
	}()
	select {
	case c := <-got:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("listener ended after transient accept errors")
	}
	if n := strings.Count(logs.String(), `"error_type":"accept_failed"`); n != 3 {
		t.Errorf("logged %d accept_failed lines, want 3", n)
	}
}

func TestMultiListenerStopsOnClosedListener(t *testing.T) {
	ln := newScriptedListener(acceptResult{err: net.ErrClosed})
	ml := newMultiListener([]net.Listener{ln}, nil, nil, "ssh")
	done := make(chan struct{})
	go func() {
		ml.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept goroutine did not stop on net.ErrClosed")
	}
	ml.Close()
}

func TestMultiListenerCloseStopsRetryLoop(t *testing.T) {
	fastAcceptBackoff(t)
	// An endless stream of errors must not keep Close from returning.
	ln := &failingListener{closed: make(chan struct{})}
	ml := newMultiListener([]net.Listener{ln}, nil, nil, "ssh")
	done := make(chan struct{})
	go func() {
		ml.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung while Accept kept failing")
	}
}

type failingListener struct {
	closed chan struct{}
	once   sync.Once
}

func (l *failingListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		return nil, errors.New("accept tcp: too many open files")
	}
}

func (l *failingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *failingListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestProxyListenerSurvivesTransientAcceptErrors(t *testing.T) {
	fastAcceptBackoff(t)
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 8.8.8.8 1.1.1.1 1234 80\r\n"))
	}()
	emfile := errors.New("accept tcp: too many open files")
	ln := newScriptedListener(acceptResult{err: emfile}, acceptResult{err: emfile}, acceptResult{conn: server})
	pl := newProxyListener(ln, nil, nil, "ssh", config.NewProxyTrust(nil, true))
	defer pl.Close()

	type res struct {
		conn net.Conn
		err  error
	}
	out := make(chan res, 1)
	go func() {
		c, err := pl.Accept()
		out <- res{c, err}
	}()
	select {
	case r := <-out:
		if r.err != nil {
			t.Fatalf("Accept failed after transient errors: %v", r.err)
		}
		if host, _ := ParseAddr(r.conn.RemoteAddr().String()); host != "8.8.8.8" {
			t.Errorf("remote = %s, want 8.8.8.8 from the PROXY header", host)
		}
		r.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("proxy listener stopped accepting after transient errors")
	}
}
