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
	// Kernel is the kernel release of the /phpinfo.php "System" line. It is
	// empty in fixed mode, which keeps the original value.
	Kernel string
	// PHPPackage is the distribution package version of PHP as phpinfo shows it
	// (for example "8.3.6-0ubuntu0.24.04.2"). It is empty in fixed mode.
	PHPPackage string
}

// PoweredBy returns the X-Powered-By header value.
func (h HTTP) PoweredBy() string { return "PHP/" + h.PHP }

// fixedKernel is the kernel release the /phpinfo.php fixture always reported
// before profiles carried one.
const fixedKernel = "5.15.0-91-generic"

// KernelRelease returns the kernel release for the /phpinfo.php "System" line.
func (h HTTP) KernelRelease() string {
	if h.Kernel == "" {
		return fixedKernel
	}
	return h.Kernel
}

// PHPInfoVersion returns the version phpinfo prints: the package version when
// the profile has one, else the plain PHP version.
func (h HTTP) PHPInfoVersion() string {
	if h.PHPPackage == "" {
		return h.PHP
	}
	return h.PHPPackage
}

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
	// Build holds the remaining root document fields. It is the zero value in
	// fixed mode, which keeps the original, shorter document.
	Build ESBuild
}

// ESBuild is the build information of the Elasticsearch root document. The
// hashes and dates are plausible values, not taken from real release artifacts.
type ESBuild struct {
	Type     string
	Hash     string
	Date     string
	Lucene   string
	MinWire  string
	MinIndex string
}

// IsZero reports whether no build information is set.
func (b ESBuild) IsZero() bool { return b == ESBuild{} }

// SendsProductHeader reports whether this version answers with the
// X-elastic-product header, which Elasticsearch added in 7.14.
func (e Elasticsearch) SendsProductHeader() bool {
	var major, minor int
	if _, err := fmt.Sscanf(e.Version, "%d.%d", &major, &minor); err != nil {
		return true
	}
	return major > 7 || (major == 7 && minor >= 14)
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
//
// Selection scores every entry by its key (see pick), not by its position, so
// reordering or inserting entries does not move the choice of other entries,
// and adding an entry takes over only about 1/(n+1) of the instances. Still:
// append only -- never insert, reorder or edit selected entries in place (a key
// change or an edited field changes the banners of existing instances on
// upgrade). TestGoldenSelection pins the result for fixed seeds; change it only
// on purpose and note the upgrade effect.
var (
	// append only -- never insert, reorder or edit selected entries in place, the golden test pins this.
	sshTable = []string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
	}

	// append only -- never insert, reorder or edit selected entries in place, the golden test pins this.
	mysqlTable = []string{
		"8.0.35",
		"8.0.37",
		"8.0.39",
		"8.0.40-0ubuntu0.22.04.1",
		"8.0.40-0ubuntu0.24.04.1",
		"5.7.42-0ubuntu0.18.04.1",
		"5.7.44",
	}

	// append only -- never insert, reorder or edit selected entries in place, the golden test pins this.
	httpTable = []HTTP{
		{Server: "Apache/2.4.58 (Ubuntu)", PHP: "8.3.6", StatusServer: "Apache/2.4.58 (Ubuntu)", Kernel: "6.8.0-45-generic", PHPPackage: "8.3.6-0ubuntu0.24.04.2"},
		{Server: "Apache/2.4.52 (Ubuntu)", PHP: "8.1.2", StatusServer: "Apache/2.4.52 (Ubuntu)", Kernel: "5.15.0-122-generic", PHPPackage: "8.1.2-1ubuntu2.18"},
		{Server: "Apache/2.4.62 (Debian)", PHP: "8.2.26", StatusServer: "Apache/2.4.62 (Debian)", Kernel: "6.1.0-27-amd64", PHPPackage: "8.2.26-1~deb12u1"},
		{Server: "Apache/2.4.57 (Debian)", PHP: "8.2.7", StatusServer: "Apache/2.4.57 (Debian)", Kernel: "6.1.0-10-amd64", PHPPackage: "8.2.7-1~deb12u1"},
		{Server: "nginx/1.24.0 (Ubuntu)", PHP: "8.3.6", Kernel: "6.8.0-45-generic", PHPPackage: "8.3.6-0ubuntu0.24.04.2"},
		{Server: "nginx/1.18.0 (Ubuntu)", PHP: "8.1.2", Kernel: "5.15.0-122-generic", PHPPackage: "8.1.2-1ubuntu2.18"},
		{Server: "nginx/1.22.1", PHP: "8.2.26", Kernel: "6.1.0-27-amd64", PHPPackage: "8.2.26-1~deb12u1"},
	}

	// append only -- never insert, reorder or edit selected entries in place, the golden test pins this.
	smtpHosts = []string{
		"mail.example.com",
		"mx1.example.net",
		"smtp.example.org",
		"relay.example.com",
		"mail01.example.net",
		"mx.example.org",
	}

	// append only -- never insert, reorder or edit selected entries in place, the golden test pins this.
	smtpSoftware = []string{
		"ESMTP Postfix (Ubuntu)",
		"ESMTP Postfix (Debian/GNU)",
		"ESMTP Postfix",
	}

	// esReleases pairs each version with its root document build fields. The
	// Lucene and compatibility versions follow the real releases; the build
	// hashes and dates are plausible placeholders and are not verified.
	// append only -- never insert, reorder or edit selected entries in place, the golden test pins this.
	esReleases = []struct {
		Version string
		Build   ESBuild
	}{
		{"8.11.4", ESBuild{Type: "docker", Hash: "da06c4d1a2d8c4b0b4a7b7e0c9a6a8b6e0b0f1e4", Date: "2024-01-18T10:05:08.044381957Z", Lucene: "9.8.0", MinWire: "7.17.0", MinIndex: "7.0.0"}},
		{"8.13.4", ESBuild{Type: "docker", Hash: "da95df118650b55a500dcc181889ac35c6d8da7c", Date: "2024-05-06T22:04:45.107454559Z", Lucene: "9.10.0", MinWire: "7.17.0", MinIndex: "7.0.0"}},
		{"8.14.3", ESBuild{Type: "docker", Hash: "d55f984299e0e88dee72ebd8255f7ff130859ad0", Date: "2024-07-07T22:04:49.882652950Z", Lucene: "9.10.0", MinWire: "7.17.0", MinIndex: "7.0.0"}},
		{"7.17.18", ESBuild{Type: "docker", Hash: "8682172c2130b9a411b1bd5ff37c9792367de6b0", Date: "2024-02-02T12:04:59.691750271Z", Lucene: "8.11.1", MinWire: "6.8.0", MinIndex: "6.0.0-beta1"}},
		{"7.17.22", ESBuild{Type: "docker", Hash: "38e9ca2e81304a821c50862dafab089ca863944b", Date: "2024-06-06T07:35:17.140964585Z", Lucene: "8.11.3", MinWire: "6.8.0", MinIndex: "6.0.0-beta1"}},
		{"7.10.2", ESBuild{Type: "docker", Hash: "747e1cc71def077253878a59143c1f785afa92b9", Date: "2021-01-13T00:42:12.435326Z", Lucene: "8.7.0", MinWire: "6.8.0", MinIndex: "6.0.0-beta1"}},
	}

	// append only -- never insert, reorder or edit selected entries in place, the golden test pins this.
	esClusters = []struct{ Cluster, Node string }{
		{"docker-cluster", "es01"},
		{"es-cluster", "es-node-1"},
		{"logging", "elasticsearch-0"},
		{"elasticsearch", "node-1"},
	}
)

// pick returns the entry of table with the highest score for (seed, label)
// (rendezvous hashing). The score is HMAC-SHA256(seed, "ran/fingerprint/v1/" +
// label + NUL + key(entry)) and so depends on the entry, not its position. Keys
// must be unique within a table.
func pick[T any](seed []byte, label string, table []T, key func(T) string) T {
	var best T
	var bestScore uint64
	for i, e := range table {
		mac := hmac.New(sha256.New, seed)
		mac.Write([]byte("ran/fingerprint/v1/" + label + "\x00" + key(e)))
		score := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
		if i == 0 || score > bestScore {
			best, bestScore = e, score
		}
	}
	return best
}

func ident(s string) string { return s }

// FromSeed derives the seeded profile for seed. The same seed always yields
// the same profile.
func FromSeed(seed []byte) *Profile {
	cl := pick(seed, "elasticsearch/cluster", esClusters, func(c struct{ Cluster, Node string }) string { return c.Cluster + "/" + c.Node })
	rel := pick(seed, "elasticsearch/version", esReleases, func(r struct {
		Version string
		Build   ESBuild
	}) string {
		return r.Version
	})
	return &Profile{
		Mode:  ModeSeeded,
		SSH:   pick(seed, "ssh", sshTable, ident),
		MySQL: pick(seed, "mysql", mysqlTable, ident),
		HTTP:  pick(seed, "http", httpTable, func(h HTTP) string { return h.Server + "|" + h.PHP }),
		SMTP: SMTP{
			Host:     pick(seed, "smtp/host", smtpHosts, ident),
			Software: pick(seed, "smtp/software", smtpSoftware, ident),
		},
		Elasticsearch: Elasticsearch{
			Version:     rel.Version,
			ClusterName: cl.Cluster,
			NodeName:    cl.Node,
			Build:       rel.Build,
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
