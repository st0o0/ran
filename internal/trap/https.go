package trap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	"path/filepath"
	"runtime"
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
	certs, err := loadOrGenerateCerts(cfg.HTTPSCertPath, logger)
	if err != nil {
		return nil, fmt.Errorf("https certificate: %w", err)
	}
	t := &HTTPSTrap{HTTPTrap: newHTTPTrap("https", cfg, logger, m, limiter, alerter)}
	// TLS handshake failures are scanner noise; they surface as probe sessions.
	t.srv.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	t.tlsCfg = &tls.Config{
		// ECDSA first, RSA for clients that only offer RSA suites; crypto/tls picks the
		// first certificate the ClientHello supports.
		Certificates: certs,
		// The trap accepts old clients (see design.md): TLS 1.0 and every suite Go
		// implements. An explicit MinVersion and CipherSuites bypass the GODEBUG
		// defaults (tls10server, tlsrsakex, tls3des).
		MinVersion:   tls.VersionTLS10, //nolint:gosec // deliberate: honeypot accepts old clients
		CipherSuites: legacyCipherSuites(),
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

// loadOrGenerateCerts loads the certificates stored in one PEM file at path: an
// ECDSA P-256 pair and an RSA-2048 pair (certificate, key, certificate, key). The
// RSA certificate lets clients that only offer RSA suites (old TLS stacks) finish
// the handshake. A missing, unreadable, invalid, expired, not yet valid or
// incomplete file is replaced by new self-signed certificates that are persisted
// (atomically, mode 0600) when path is writable and otherwise kept in memory (a
// warning is logged and startup does not fail).
func loadOrGenerateCerts(path string, logger *slog.Logger) ([]tls.Certificate, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			certs, perr := parseCertPairs(data, time.Now())
			if perr == nil {
				logger.Info("loaded https certificate", "path", path)
				return certs, nil
			}
			logger.Warn("https certificate unusable, generating a new one", "path", path, "error", perr)
		case !errors.Is(err, os.ErrNotExist):
			logger.Warn("cannot read https certificate, generating a new one; check the file permissions (the volume must be writable by uid 65532)", "path", path, "error", err)
		}
	}

	now := time.Now()
	certs, pemData, err := generateCerts(now.Add(-time.Hour), now.Add(certValidity))
	if err != nil {
		return nil, err
	}
	if path != "" {
		if werr := writeFileAtomic(path, pemData); werr == nil {
			logger.Info("persisted https certificate", "path", path)
			return certs, nil
		} else {
			logger.Warn("cannot persist https certificate; it changes on every restart. If /data is a root-owned volume from an older release, fix it with: chown -R 65532:65532 on the volume",
				"path", path, "error", werr)
		}
	}
	logger.Info("generated ephemeral https certificate")
	return certs, nil
}

// parseCertPairs reads certificate/key pairs in file order and returns the ECDSA
// pair followed by the RSA pair. Every pair must be valid at now.
func parseCertPairs(data []byte, now time.Time) ([]tls.Certificate, error) {
	var ecCert, rsaCert *tls.Certificate
	var pending []byte
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		enc := pem.EncodeToMemory(blk)
		if blk.Type == "CERTIFICATE" {
			pending = enc
			continue
		}
		if pending == nil {
			return nil, errors.New("private key without certificate")
		}
		cert, err := tls.X509KeyPair(pending, enc)
		pending = nil
		if err != nil {
			return nil, err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return nil, errors.New("certificate expired or not yet valid")
		}
		cert.Leaf = leaf
		switch leaf.PublicKey.(type) {
		case *ecdsa.PublicKey:
			ecCert = &cert
		case *rsa.PublicKey:
			rsaCert = &cert
		}
	}
	if ecCert == nil || rsaCert == nil {
		return nil, errors.New("file needs one ECDSA and one RSA certificate")
	}
	return []tls.Certificate{*ecCert, *rsaCert}, nil
}

// writeFileAtomic writes data to a temporary file next to path (mode 0600),
// syncs it and renames it over path, so readers never see a partial file and an
// existing file with looser permissions ends up 0600.
func writeFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".https_cert-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// generateCerts creates self-signed certificates for "localhost" (ECDSA P-256 and
// RSA-2048) that do not imitate any real host. The PEM holds certificate and key
// of the ECDSA pair, then of the RSA pair.
func generateCerts(notBefore, notAfter time.Time) ([]tls.Certificate, []byte, error) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	var pemData []byte
	var certs []tls.Certificate
	for _, key := range []crypto.Signer{ecKey, rsaKey} {
		p, err := selfSignedPEM(key, notBefore, notAfter)
		if err != nil {
			return nil, nil, err
		}
		cert, err := tls.X509KeyPair(p, p)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		pemData = append(pemData, p...)
	}
	return certs, pemData, nil
}

// selfSignedPEM returns a certificate and PKCS#8 key (PEM) for key.
func selfSignedPEM(key crypto.Signer, notBefore, notAfter time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...), nil
}

// legacyCipherSuites lists every suite crypto/tls implements, including the ones
// it no longer enables by default (RSA key exchange, 3DES, RC4, CBC-SHA256), so
// old scanners and clients can finish the handshake. TLS 1.3 suites are not
// configurable and always on.
func legacyCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}
