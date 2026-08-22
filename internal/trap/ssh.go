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
	"sync"

	"crypto/x509"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	gossh "golang.org/x/crypto/ssh"
)


type SSHTrap struct {
	cfg      *config.Config
	logger   *slog.Logger
	metrics  *metrics.Metrics
	limiter  *Limiter
	alerter  alert.Alerter
	signer   gossh.Signer
	listener *MultiListener
	wg       sync.WaitGroup
}

func NewSSH(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter alert.Alerter) (*SSHTrap, error) {
	signer, err := loadOrGenerateHostKey(cfg.SSHHostKeyPath, logger)
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}
	return &SSHTrap{
		cfg:     cfg,
		logger:  logger,
		metrics: m,
		limiter: limiter,
		alerter: alerter,
		signer:  signer,
	}, nil
}

func (t *SSHTrap) Start(ctx context.Context) error {
	ln, err := ListenMultiTCP(ctx, t.cfg.TrapAddrs("ssh"), t.cfg.ProxyProtocol)
	if err != nil {
		return fmt.Errorf("ssh listen: %w", err)
	}
	t.listener = ln
	t.logger.Info("listening", "addrs", t.cfg.TrapAddrs("ssh"))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			LogErrorStandalone(t.logger, "ssh", "accept_failed", err)
			continue
		}
		t.wg.Add(1)
		go t.handle(ctx, conn)
	}
	return nil
}

func (t *SSHTrap) Stop(_ context.Context) error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
	return nil
}

func (t *SSHTrap) handle(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	host, port := ParseAddr(conn.RemoteAddr().String())
	_, destPort := ParseAddr(conn.LocalAddr().String())
	sess := NewSession("ssh", "tcp", host, port, destPort, t.logger)

	if !t.limiter.Acquire(host) {
		LogRejected(t.logger, "ssh", "tcp", destPort, host, "rate_limit")
		return
	}
	defer t.limiter.Release(host)

	sess.LogConnect()
	sess.RecordStart(t.metrics)
	defer sess.RecordEnd(t.metrics)
	defer sess.LogDisconnect()

	_ = conn.SetDeadline(deadlineFromContext(ctx, t.cfg.SessionTimeout))

	sshCfg := &gossh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.6",
		PasswordCallback: func(c gossh.ConnMetadata, pass []byte) (*gossh.Permissions, error) {
			sess.LogAuthAttempt(
				slog.String("username", c.User()),
				slog.String("password", string(pass)),
			)
			sess.RecordCredentials(t.metrics)
			t.alerter.Alert(ctx, host, "ssh", map[string]string{"username": c.User(), "password": string(pass)})
			return nil, errors.New("access denied")
		},
	}
	sshCfg.AddHostKey(t.signer)

	sshConn, _, _, err := gossh.NewServerConn(conn, sshCfg)
	if err != nil {
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			sess.SetOutcome("timeout")
		} else {
			sess.SetOutcome("error")
		}
		sess.LogError("handshake_failed", err)
		return
	}
	sshConn.Close()
}

func loadOrGenerateHostKey(path string, logger *slog.Logger) (gossh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := gossh.ParsePrivateKey(data)
		if err == nil {
			logger.Info("loaded ssh host key", "path", path)
			return key, nil
		}
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
		if writeErr := os.WriteFile(path, pemBlock, 0600); writeErr == nil {
			logger.Info("persisted ssh host key", "path", path)
		}
	}

	logger.Info("generated ephemeral ssh host key")
	return signer, nil
}
