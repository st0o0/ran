package trap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"crypto/x509"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/fingerprint"
	"github.com/st0o0/ran/internal/metrics"
	gossh "golang.org/x/crypto/ssh"
)

type SSHTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	signer  gossh.Signer
	fp      *fingerprint.Profile
}

func NewSSH(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) (*SSHTrap, error) {
	signer, err := loadOrGenerateHostKey(cfg.SSHHostKeyPath, logger)
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}
	t := &SSHTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		signer:  signer,
		fp:      cfg.Fingerprint(logger),
	}
	t.tcpServer = newTCPServer("ssh", cfg, logger, m, limiter, alerter, t.handle)
	return t, nil
}

func (t *SSHTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	if t.cfg.SSHTarpit {
		timeout := t.cfg.ResolveSessionTimeout("ssh")
		duration, capped := tarpitDuration(t.cfg.SSHTarpitDuration, timeout)
		if err := sshTarpit(ctx, conn, duration); err != nil {
			if ctx.Err() != nil {
				sess.SetOutcome("timeout")
			} else {
				setOutcome(sess, err)
			}
			return
		}
		if capped {
			// The tarpit used up the whole session time: end the session here
			// instead of letting the last write hit the connection deadline.
			sess.SetOutcome("timeout")
			return
		}
		sess.Deadline = deadlineFromContext(ctx, timeout)
		_ = conn.SetDeadline(sess.Deadline)
	}

	var authSeen bool
	var attempt int
	authDelay := t.cfg.ResolveAuthDelay("ssh")
	maxRetries := sshMaxAuthTries(t.cfg.ResolveMaxAuthRetries("ssh"))

	sniff := newKexSniffConn(conn)

	// identity returns the log attributes and alert meta that describe the
	// client implementation: version string and HASSH, both bounded.
	identity := func(c gossh.ConnMetadata) (attrs []slog.Attr, meta map[string]string) {
		meta = map[string]string{"username": c.User()}
		if v := sanitizeClientVersion(string(c.ClientVersion())); v != "" {
			attrs = append(attrs, slog.String("client_version", v))
			meta["client_version"] = v
		}
		if h := sniff.HASSH(); h != "" {
			attrs = append(attrs, slog.String("hassh", h))
			meta["hassh"] = h
		}
		return attrs, meta
	}

	// record logs, counts and reports one rejected attempt and applies the
	// auth delay. A secret is passed only as a "password" log attribute, so
	// RAN_LOG_PASSWORDS governs it, and is never added to the alert meta.
	record := func(c gossh.ConnMetadata, method string, extra []slog.Attr, extraMeta map[string]string) error {
		authSeen = true
		idAttrs, meta := identity(c)
		attrs := append([]slog.Attr{slog.String("username", alert.SanitizeValue(c.User())), slog.String("method", method)}, extra...)
		attrs = append(attrs, idAttrs...)
		sess.LogAuthAttempt(attrs...)
		sess.RecordCredentials(t.metrics)
		meta["method"] = method
		for k, v := range extraMeta {
			meta[k] = v
		}
		sess.Alert(ctx, meta)
		if authDelay > 0 {
			_ = sess.authSleep(ctx, authDelay, attempt)
		}
		attempt++
		return errors.New("access denied")
	}

	sshCfg := &gossh.ServerConfig{
		ServerVersion: t.fp.SSH,
		MaxAuthTries:  maxRetries,
		PasswordCallback: func(c gossh.ConnMetadata, pass []byte) (*gossh.Permissions, error) {
			authSeen = true
			idAttrs, meta := identity(c)
			attrs := append([]slog.Attr{
				slog.String("username", alert.SanitizeValue(c.User())),
				slog.String("method", "password"),
				slog.String("password", string(pass)),
			}, idAttrs...)
			sess.LogAuthAttempt(attrs...)
			sess.RecordCredentials(t.metrics)
			meta["method"] = "password"
			meta["password"] = string(pass)
			sess.Alert(ctx, meta)
			if authDelay > 0 {
				_ = sess.authSleep(ctx, authDelay, attempt)
			}
			attempt++
			return nil, errors.New("access denied")
		},
		// x/crypto caches the result per (user, key), so each distinct key is
		// logged once even though clients query and then sign.
		PublicKeyCallback: func(c gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			keyType := alert.SanitizeValue(key.Type())
			fp := gossh.FingerprintSHA256(key)
			return nil, record(c, "publickey",
				[]slog.Attr{slog.String("key_type", keyType), slog.String("fingerprint", fp)},
				map[string]string{"key_type": keyType, "fingerprint": fp})
		},
		KeyboardInteractiveCallback: func(c gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, record(c, "keyboard-interactive", nil, nil)
			}
			var extra []slog.Attr
			if len(answers) > 0 {
				extra = append(extra, slog.String("password", answers[0]))
			}
			return nil, record(c, "keyboard-interactive", extra, nil)
		},
	}
	sshCfg.AddHostKey(t.signer)

	sshConn, _, _, err := gossh.NewServerConn(sniff, sshCfg)
	if err != nil {
		if authSeen {
			sess.SetOutcome("completed")
		} else {
			setOutcome(sess, err)
		}
		if !authSeen {
			sess.LogError("handshake_failed", err)
		}
		return
	}
	sshConn.Close()
}

// sshMaxAuthTries maps RAN_MAX_AUTH_RETRIES to x/crypto's MaxAuthTries. The
// library treats 0 as "use 6" and any negative value as unlimited, while the
// setting means 0 = unlimited (as for telnet and mssql).
func sshMaxAuthTries(retries int) int {
	if retries == 0 {
		return -1
	}
	return retries
}

// tarpitSessionMargin is kept free at the end of the session time when the
// tarpit would otherwise run into the connection deadline.
const tarpitSessionMargin = 250 * time.Millisecond

// tarpitDuration limits the tarpit to the session timeout. capped reports that
// the limit applied, so the tarpit ends before the connection deadline.
func tarpitDuration(duration, timeout time.Duration) (d time.Duration, capped bool) {
	if duration < timeout {
		return duration, false
	}
	margin := min(tarpitSessionMargin, timeout/10)
	return timeout - margin, true
}

// sshTarpit writes a random 32 character line every 10 seconds until duration
// has elapsed and then returns nil. It returns the write error, or ctx.Err()
// when ctx ends first.
func sshTarpit(ctx context.Context, conn net.Conn, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	for {
		select {
		case <-deadline.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := make([]byte, 32)
		randBytes := make([]byte, 32)
		_, _ = rand.Read(randBytes)
		for i := range line {
			line[i] = '!' + randBytes[i]%('~'-'!'+1)
		}
		if line[0] == 'S' && len(line) > 3 && line[1] == 'S' && line[2] == 'H' && line[3] == '-' {
			line[0] = 'X'
		}
		line = append(line, '\r', '\n')
		if _, err := conn.Write(line); err != nil {
			return err
		}
		wait := time.NewTimer(10 * time.Second)
		select {
		case <-deadline.C:
			wait.Stop()
			return nil
		case <-ctx.Done():
			wait.Stop()
			return ctx.Err()
		case <-wait.C:
		}
	}
}

func loadOrGenerateHostKey(path string, logger *slog.Logger) (gossh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, perr := gossh.ParsePrivateKey(data)
		if perr == nil {
			logger.Info("loaded ssh host key", "path", path)
			return key, nil
		}
		logger.Warn("ssh host key unreadable, generating a new one", "path", path, "error", perr)
	} else if !errors.Is(err, os.ErrNotExist) {
		logger.Warn("cannot read ssh host key, generating a new one; check the file permissions (the volume must be writable by uid 65532)", "path", path, "error", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err == nil {
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		writeErr := os.WriteFile(path, pemBlock, 0600)
		if writeErr == nil {
			logger.Info("persisted ssh host key", "path", path)
			return signer, nil
		}
		logger.Warn("cannot persist ssh host key; it changes on every restart and clients will see a host key warning. If /data is a root-owned volume from an older release, fix it with: chown -R 65532:65532 on the volume",
			"path", path, "error", writeErr)
	}

	logger.Info("generated ephemeral ssh host key")
	return signer, nil
}
