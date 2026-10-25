// Package fingerprint selects the version strings the traps present. A profile
// is derived from a persisted seed, so an instance keeps its banners across
// restarts while different instances differ. Fixed mode keeps the original
// values for operators who parse them.
package fingerprint

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Modes of RAN_FINGERPRINT.
const (
	ModeSeeded = "seeded"
	ModeFixed  = "fixed"
)

// SeedSize is the size of the seed in bytes.
const SeedSize = 32

// HTTP describes the web server of the http and https traps and of their
// fixtures. Server, PHP and StatusServer belong together.
type HTTP struct {
	// Server is the Server response header.
	Server string
	// PHP is the PHP version; the X-Powered-By header is "PHP/" + PHP.
	PHP string
	// StatusServer is the "Server Version" line of the /server-status fixture.
	// It is empty for servers without mod_status (nginx), which then do not
	// serve that fixture.
	StatusServer string
}

// PoweredBy returns the X-Powered-By header value.
func (h HTTP) PoweredBy() string { return "PHP/" + h.PHP }

// SMTP describes the SMTP greeting: "220 <Host> <Software>".
type SMTP struct {
	Host     string
	Software string
}

// Greeting returns the 220 line without CRLF.
func (s SMTP) Greeting() string { return "220 " + s.Host + " " + s.Software }

// Elasticsearch describes the root document of the elasticsearch trap.
type Elasticsearch struct {
	Version     string
	ClusterName string
	NodeName    string
}

// Profile holds every version string a trap presents. Fields are read only.
type Profile struct {
	Mode string
	// SSH is the full identification string, including the "SSH-2.0-" prefix.
	SSH           string
	MySQL         string
	HTTP          HTTP
	SMTP          SMTP
	Elasticsearch Elasticsearch
}

// Fixed returns the profile with the original, fixed values.
func Fixed() *Profile {
	return &Profile{
		Mode:          ModeFixed,
		SSH:           "SSH-2.0-OpenSSH_9.6",
		MySQL:         "8.0.36",
		HTTP:          HTTP{Server: "Apache/2.4.62", PHP: "8.3.6", StatusServer: "Apache/2.4.62 (Unix)"},
		SMTP:          SMTP{Host: "mx.localdomain", Software: "ESMTP ready"},
		Elasticsearch: Elasticsearch{Version: "8.12.0", ClusterName: "elasticsearch", NodeName: "node-1"},
	}
}

// The tables hold plausible values as real distributions ship them. Each entry
// is consistent in itself (an Apache or nginx build with the PHP of the same
// distribution release); entries of different traps are chosen independently.
var (
	sshTable = []string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
	}

	mysqlTable = []string{
		"8.0.35",
		"8.0.37",
		"8.0.39",
		"8.0.40-0ubuntu0.22.04.1",
		"8.0.40-0ubuntu0.24.04.1",
		"5.7.42-0ubuntu0.18.04.1",
		"5.7.44",
	}

	httpTable = []HTTP{
		{Server: "Apache/2.4.58 (Ubuntu)", PHP: "8.3.6", StatusServer: "Apache/2.4.58 (Ubuntu)"},
		{Server: "Apache/2.4.52 (Ubuntu)", PHP: "8.1.2", StatusServer: "Apache/2.4.52 (Ubuntu)"},
		{Server: "Apache/2.4.62 (Debian)", PHP: "8.2.26", StatusServer: "Apache/2.4.62 (Debian)"},
		{Server: "Apache/2.4.57 (Debian)", PHP: "8.2.7", StatusServer: "Apache/2.4.57 (Debian)"},
		{Server: "nginx/1.24.0 (Ubuntu)", PHP: "8.3.6"},
		{Server: "nginx/1.18.0 (Ubuntu)", PHP: "8.1.2"},
		{Server: "nginx/1.22.1", PHP: "8.2.26"},
	}

	smtpHosts = []string{
		"mail.example.com",
		"mx1.example.net",
		"smtp.example.org",
		"relay.example.com",
		"mail01.example.net",
		"mx.example.org",
	}

	smtpSoftware = []string{
		"ESMTP Postfix (Ubuntu)",
		"ESMTP Postfix (Debian/GNU)",
		"ESMTP Postfix",
	}

	esVersions = []string{
		"8.11.4",
		"8.13.4",
		"8.14.3",
		"7.17.18",
		"7.17.22",
		"7.10.2",
	}

	esClusters = []struct{ Cluster, Node string }{
		{"docker-cluster", "es01"},
		{"es-cluster", "es-node-1"},
		{"logging", "elasticsearch-0"},
		{"elasticsearch", "node-1"},
	}
)

// pick returns a deterministic index in [0, n) for (seed, label).
func pick(seed []byte, label string, n int) int {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("ran/fingerprint/v1/" + label))
	return int(binary.BigEndian.Uint64(mac.Sum(nil)[:8]) % uint64(n))
}

// FromSeed derives the seeded profile for seed. The same seed always yields
// the same profile.
func FromSeed(seed []byte) *Profile {
	cl := esClusters[pick(seed, "elasticsearch/cluster", len(esClusters))]
	return &Profile{
		Mode:  ModeSeeded,
		SSH:   sshTable[pick(seed, "ssh", len(sshTable))],
		MySQL: mysqlTable[pick(seed, "mysql", len(mysqlTable))],
		HTTP:  httpTable[pick(seed, "http", len(httpTable))],
		SMTP: SMTP{
			Host:     smtpHosts[pick(seed, "smtp/host", len(smtpHosts))],
			Software: smtpSoftware[pick(seed, "smtp/software", len(smtpSoftware))],
		},
		Elasticsearch: Elasticsearch{
			Version:     esVersions[pick(seed, "elasticsearch/version", len(esVersions))],
			ClusterName: cl.Cluster,
			NodeName:    cl.Node,
		},
	}
}

// Load returns the profile for mode. In seeded mode the seed is read from
// path; a missing, unreadable, corrupt or short file is replaced by a new seed
// that is persisted (atomically, mode 0600). When the file cannot be written
// the seed is kept in memory and a warning is logged; Load never fails.
func Load(mode, path string, logger *slog.Logger) *Profile {
	if mode != ModeSeeded {
		return Fixed()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return FromSeed(loadOrCreateSeed(path, logger))
}

func loadOrCreateSeed(path string, logger *slog.Logger) []byte {
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			seed, perr := parseSeed(data)
			if perr == nil {
				logger.Info("loaded fingerprint seed", "path", path)
				return seed
			}
			logger.Warn("fingerprint seed unusable, generating a new one", "path", path, "error", perr)
		case !errors.Is(err, os.ErrNotExist):
			logger.Warn("cannot read fingerprint seed, generating a new one; check the file permissions (the volume must be writable by uid 65532)", "path", path, "error", err)
		}
	}

	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		// crypto/rand does not fail on supported platforms; a zero seed is
		// still a valid, stable profile and beats aborting startup.
		logger.Warn("cannot read random bytes for the fingerprint seed", "error", err)
	}
	if path == "" {
		logger.Warn("no fingerprint seed path; using an ephemeral seed, banners change on every restart")
		return seed
	}
	if err := writeFileAtomic(path, []byte(hex.EncodeToString(seed)+"\n")); err != nil {
		logger.Warn("cannot persist fingerprint seed; banners change on every restart. If /data is a root-owned volume from an older release, fix it with: chown -R 65532:65532 on the volume",
			"path", path, "error", err)
		return seed
	}
	logger.Info("persisted fingerprint seed", "path", path)
	return seed
}

func parseSeed(data []byte) ([]byte, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("seed has %d bytes, want %d", len(seed), SeedSize)
	}
	return seed, nil
}

// writeFileAtomic writes data to a temporary file next to path (mode 0600),
// syncs it and renames it over path.
func writeFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".fingerprint_seed-*.tmp")
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
