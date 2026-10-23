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

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	gossh "golang.org/x/crypto/ssh"
)

type SSHTrap struct {
	*tcpServer
	cfg     *config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
	signer  gossh.Signer
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
	}
	t.tcpServer = newTCPServer("ssh", cfg, logger, m, limiter, alerter, t.handle)
	return t, nil
}

func (t *SSHTrap) handle(ctx context.Context, conn net.Conn, sess *Session) {
	if t.cfg.SSHTarpit {
		tarpitCtx, tarpitCancel := context.WithTimeout(ctx, t.cfg.SSHTarpitDuration)
		err := sshTarpit(tarpitCtx, conn, t.cfg.SSHTarpitDuration)
		tarpitCancel()
		if err != nil {
			if ctx.Err() != nil {
				sess.SetOutcome("timeout")
			} else {
				sess.SetOutcome("error")
			}
			return
		}
		timeout := t.cfg.ResolveSessionTimeout("ssh")
		_ = conn.SetDeadline(deadlineFromContext(ctx, timeout))
	}

	var authSeen bool
	var attempt int
	authDelay := t.cfg.ResolveAuthDelay("ssh")
	maxRetries := t.cfg.ResolveMaxAuthRetries("ssh")

	sshCfg := &gossh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.6",
		MaxAuthTries:  maxRetries,
		PasswordCallback: func(c gossh.ConnMetadata, pass []byte) (*gossh.Permissions, error) {
			authSeen = true
			sess.LogAuthAttempt(
				slog.String("username", c.User()),
				slog.String("password", string(pass)),
			)
			sess.RecordCredentials(t.metrics)
			sess.Alert(ctx, map[string]string{"username": c.User(), "password": string(pass)})
			if authDelay > 0 {
				if err := authSleep(ctx, authDelay, attempt); err != nil {
					attempt++
					return nil, errors.New("access denied")
				}
			}
			attempt++
			return nil, errors.New("access denied")
		},
	}
	sshCfg.AddHostKey(t.signer)

	sshConn, _, _, err := gossh.NewServerConn(conn, sshCfg)
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

func sshTarpit(ctx context.Context, conn net.Conn, duration time.Duration) error {
	deadline := time.After(duration)
	for {
		select {
		case <-deadline:
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
		case <-deadline:
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
