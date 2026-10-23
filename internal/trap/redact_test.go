package trap

import (
	"log/slog"
	"strings"
	"testing"
)

func TestLogCommandRedactsCredentials(t *testing.T) {
	lines := []struct {
		line   string
		secret string
	}{
		{"a1 AUTHENTICATE PLAIN c2VjcmV0cGFzcw==", "c2VjcmV0cGFzcw=="},
		{"a2 LOGIN alice hunter2", "hunter2"},
		{"PASS hunter2", "hunter2"},
		{"OPER admin hunter2", "hunter2"},
		{"AUTHENTICATE c2VjcmV0cGFzcw==", "c2VjcmV0cGFzcw=="},
		{"PRIVMSG NickServ :IDENTIFY hunter2", "hunter2"},
		{"AUTH hunter2", "hunter2"},
		{"HELLO 3 AUTH default hunter2", "hunter2"},
		{"MIGRATE host 6379 key 0 5000 AUTH2 user hunter2", "hunter2"},
		{"CONFIG SET requirepass hunter2", "hunter2"},
	}
	old := passwordMode.Load()
	defer passwordMode.Store(old)

	for _, mode := range []string{"off", "mask"} {
		SetPasswordLogMode(mode)
		for _, c := range lines {
			buf := &syncBuffer{}
			sess := NewSession("imap", "tcp", "8.8.8.8", 1234, 143, slog.New(slog.NewTextHandler(buf, nil)))
			sess.LogCommand(c.line)
			out := buf.String()
			if strings.Contains(out, c.secret) {
				t.Errorf("mode %s: secret leaked for %q: %s", mode, c.line, out)
			}
			if !strings.Contains(out, "command") {
				t.Errorf("mode %s: command not logged for %q", mode, c.line)
			}
			if mode == "mask" && !strings.Contains(out, "***") {
				t.Errorf("mode mask: no mask for %q: %s", c.line, out)
			}
		}
	}

	SetPasswordLogMode("on")
	buf := &syncBuffer{}
	sess := NewSession("imap", "tcp", "8.8.8.8", 1234, 143, slog.New(slog.NewTextHandler(buf, nil)))
	sess.LogCommand("a2 LOGIN alice hunter2")
	if !strings.Contains(buf.String(), "hunter2") {
		t.Errorf("mode on must log the line as is: %s", buf.String())
	}
}

func TestRedactCommandKeepsPlainCommands(t *testing.T) {
	old := passwordMode.Load()
	defer passwordMode.Store(old)
	SetPasswordLogMode("off")
	for _, line := range []string{"a3 SELECT INBOX", "GET key", "JOIN #chan", "AUTH", "stats  items"} {
		if got := redactCommand(line); got != line {
			t.Errorf("redactCommand(%q) = %q, want unchanged", line, got)
		}
	}
}
