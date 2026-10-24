package trap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// HTTPSTrap is the HTTP trap behind crypto/tls. It reuses the HTTP request
// handling, session keying and shutdown of HTTPTrap; only the listener differs.
type HTTPSTrap struct {
	*HTTPTrap
	tlsCfg *tls.Config
}

func NewHTTPS(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) (*HTTPSTrap, error) {
	cert, err := loadOrGenerateCert(cfg.HTTPSCertPath, logger)
	if err != nil {
		return nil, fmt.Errorf("https certificate: %w", err)
	}
	t := &HTTPSTrap{HTTPTrap: newHTTPTrap("https", cfg, logger, m, limiter, alerter)}
	t.tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Runs after the whole ClientHello was read and before the version and
		// cipher negotiation, so hellos that fail the handshake are fingerprinted
		// as well. Returning nil keeps this config.
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if hc, ok := chi.Conn.(*helloConn); ok {
				hc.finish(chi.ServerName)
			}
			return nil, nil
		},
	}
	t.wrap = func(ln net.Listener) net.Listener { return &helloListener{Listener: ln, cfg: t.tlsCfg} }
	return t, nil
}

// helloListener wraps accepted connections so the ClientHello can be captured and
// then hands them to crypto/tls. The result is a *tls.Conn, which http.Server
// handshakes under its read deadline (the session timeout).
type helloListener struct {
	net.Listener
	cfg *tls.Config
}

func (l *helloListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(&helloConn{Conn: conn}, l.cfg), nil
}

// fingerprintAttrs returns the non-empty fingerprint fields as log attributes.
func fingerprintAttrs(fp *tlsFingerprint) []slog.Attr {
	var out []slog.Attr
	for _, kv := range [][2]string{{"sni", fp.SNI}, {"ja3", fp.JA3}, {"ja4", fp.JA4}, {"alpn", fp.ALPN}} {
		if kv[1] != "" {
			out = append(out, slog.String(kv[0], kv[1]))
		}
	}
	return out
}

const certValidity = 10 * 365 * 24 * time.Hour

// loadOrGenerateCert loads the certificate and key stored in one PEM file at path.
// A missing, unreadable, invalid or expired file is replaced by a new self-signed
// ECDSA certificate that is persisted when path is writable and otherwise kept in
// memory (a warning is logged and startup does not fail).
func loadOrGenerateCert(path string, logger *slog.Logger) (tls.Certificate, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			cert, perr := tls.X509KeyPair(data, data)
			if perr == nil {
				if leaf, lerr := x509.ParseCertificate(cert.Certificate[0]); lerr == nil && time.Now().Before(leaf.NotAfter) {
					cert.Leaf = leaf
					logger.Info("loaded https certificate", "path", path)
					return cert, nil
				}
				perr = errors.New("certificate expired or unparsable")
			}
			logger.Warn("https certificate unusable, generating a new one", "path", path, "error", perr)
		case !errors.Is(err, os.ErrNotExist):
			logger.Warn("cannot read https certificate, generating a new one; check the file permissions (the volume must be writable by uid 65532)", "path", path, "error", err)
		}
	}

	cert, pemData, err := generateCert()
	if err != nil {
		return tls.Certificate{}, err
	}
	if path != "" {
		if werr := os.WriteFile(path, pemData, 0o600); werr == nil {
			logger.Info("persisted https certificate", "path", path)
			return cert, nil
		} else {
			logger.Warn("cannot persist https certificate; it changes on every restart. If /data is a root-owned volume from an older release, fix it with: chown -R 65532:65532 on the volume",
				"path", path, "error", werr)
		}
	}
	logger.Info("generated ephemeral https certificate")
	return cert, nil
}

// generateCert creates a self-signed ECDSA P-256 certificate for "localhost". It
// does not imitate any real host. The PEM holds the certificate and the key.
func generateCert() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pemData := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, pemData, nil
}
