package fingerprint

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, SeedSize) }

func TestFixedProfileIsTheOriginalValues(t *testing.T) {
	t.Parallel()
	p := Fixed()
	checks := map[string][2]string{
		"ssh":          {p.SSH, "SSH-2.0-OpenSSH_9.6"},
		"mysql":        {p.MySQL, "8.0.36"},
		"http server":  {p.HTTP.Server, "Apache/2.4.62"},
		"http php":     {p.HTTP.PoweredBy(), "PHP/8.3.6"},
		"http status":  {p.HTTP.StatusServer, "Apache/2.4.62 (Unix)"},
		"smtp":         {p.SMTP.Greeting(), "220 mx.localdomain ESMTP ready"},
		"es version":   {p.Elasticsearch.Version, "8.12.0"},
		"es cluster":   {p.Elasticsearch.ClusterName, "elasticsearch"},
		"es node name": {p.Elasticsearch.NodeName, "node-1"},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
	if p.Mode != ModeFixed {
		t.Errorf("mode = %q", p.Mode)
	}
}

func TestSameSeedSameProfile(t *testing.T) {
	t.Parallel()
	for i := range 50 {
		seed := seedOf(byte(i))
		a, b := FromSeed(seed), FromSeed(append([]byte(nil), seed...))
		if *a != *b {
			t.Fatalf("seed %d: profiles differ: %+v vs %+v", i, a, b)
		}
	}
}

func TestDifferentSeedsDiffer(t *testing.T) {
	t.Parallel()
	seen := map[Profile]bool{}
	for i := range 64 {
		seen[*FromSeed(seedOf(byte(i)))] = true
	}
	// 64 seeds over a table product of well over 100k combinations: nearly all differ.
	if len(seen) < 60 {
		t.Errorf("only %d distinct profiles for 64 seeds", len(seen))
	}
}

func TestEveryTableValueIsReachable(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(1))
	ssh, mysql, httpSeen := map[string]bool{}, map[string]bool{}, map[HTTP]bool{}
	hosts, software, esv, clusters := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for range 4000 {
		seed := make([]byte, SeedSize)
		rng.Read(seed)
		p := FromSeed(seed)
		ssh[p.SSH] = true
		mysql[p.MySQL] = true
		httpSeen[p.HTTP] = true
		hosts[p.SMTP.Host] = true
		software[p.SMTP.Software] = true
		esv[p.Elasticsearch.Version] = true
		clusters[p.Elasticsearch.ClusterName+"/"+p.Elasticsearch.NodeName] = true
	}
	for _, v := range sshTable {
		if !ssh[v] {
			t.Errorf("ssh %q never selected", v)
		}
	}
	for _, v := range mysqlTable {
		if !mysql[v] {
			t.Errorf("mysql %q never selected", v)
		}
	}
	for _, v := range httpTable {
		if !httpSeen[v] {
			t.Errorf("http %+v never selected", v)
		}
	}
	for _, v := range smtpHosts {
		if !hosts[v] {
			t.Errorf("smtp host %q never selected", v)
		}
	}
	for _, v := range smtpSoftware {
		if !software[v] {
			t.Errorf("smtp software %q never selected", v)
		}
	}
	for _, v := range esVersions {
		if !esv[v] {
			t.Errorf("es version %q never selected", v)
		}
	}
	for _, v := range esClusters {
		if !clusters[v.Cluster+"/"+v.Node] {
			t.Errorf("es cluster %+v never selected", v)
		}
	}
}

func TestShortOrOddSeedsDoNotPanic(t *testing.T) {
	t.Parallel()
	for _, seed := range [][]byte{nil, {}, {1}, make([]byte, 100)} {
		if FromSeed(seed) == nil {
			t.Error("nil profile")
		}
	}
}

var (
	printableASCII = regexp.MustCompile(`^[\x20-\x7e]+$`)
	ipLike         = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	// Hosts may only use the names reserved for documentation (RFC 2606).
	reservedHost = regexp.MustCompile(`^[a-z0-9]+\.example\.(com|net|org)$`)
)

func TestTableEntriesAreWellFormed(t *testing.T) {
	t.Parallel()
	var all []string
	all = append(all, sshTable...)
	all = append(all, mysqlTable...)
	for _, h := range httpTable {
		all = append(all, h.Server, h.PHP, h.PoweredBy(), h.StatusServer)
		if h.Server == "" || h.PHP == "" {
			t.Errorf("incomplete http entry %+v", h)
		}
	}
	all = append(all, smtpHosts...)
	all = append(all, smtpSoftware...)
	all = append(all, esVersions...)
	for _, c := range esClusters {
		all = append(all, c.Cluster, c.Node)
	}
	for _, s := range all {
		if s == "" {
			continue // StatusServer of nginx entries is empty by design
		}
		if !printableASCII.MatchString(s) {
			t.Errorf("%q is not printable ASCII", s)
		}
		if ipLike.MatchString(s) {
			t.Errorf("%q looks like an IP address", s)
		}
		if strings.ContainsAny(s, "@\r\n\"\\") {
			t.Errorf("%q contains a forbidden character", s)
		}
	}
	for _, v := range sshTable {
		if !strings.HasPrefix(v, "SSH-2.0-OpenSSH_") {
			t.Errorf("ssh %q has no OpenSSH identification", v)
		}
	}
	for _, h := range smtpHosts {
		if !reservedHost.MatchString(h) {
			t.Errorf("smtp host %q is not a reserved example name", h)
		}
	}
	for _, h := range httpTable {
		apache := strings.HasPrefix(h.Server, "Apache/")
		if apache != (h.StatusServer != "") {
			t.Errorf("http %+v: mod_status line must exist exactly for Apache", h)
		}
		if apache && !strings.HasPrefix(h.StatusServer, h.Server) {
			t.Errorf("http %+v: status line disagrees with the Server header", h)
		}
	}
	for _, tbl := range []map[string]int{dups(sshTable), dups(mysqlTable), dups(smtpHosts), dups(smtpSoftware), dups(esVersions)} {
		for v, n := range tbl {
			if n > 1 {
				t.Errorf("duplicate table entry %q", v)
			}
		}
	}
}

func dups(in []string) map[string]int {
	m := map[string]int{}
	for _, s := range in {
		m[s]++
	}
	return m
}

func TestLoadFixedDoesNotTouchTheFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "seed")
	p := Load(ModeFixed, path, nil)
	if *p != *Fixed() {
		t.Errorf("fixed mode returned %+v", p)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("fixed mode created the seed file (stat err = %v)", err)
	}
}

func TestSeedPersistsAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "fingerprint_seed")
	var logs bytes.Buffer
	first := Load(ModeSeeded, path, testLogger(&logs))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("seed file not written: %v (%s)", err, logs.String())
	}
	if len(strings.TrimSpace(string(raw))) != SeedSize*2 {
		t.Errorf("seed file holds %q", raw)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", st.Mode().Perm())
		}
	}
	for range 3 {
		again := Load(ModeSeeded, path, testLogger(&logs))
		if *again != *first {
			t.Fatalf("restart changed the profile: %+v vs %+v", again, first)
		}
	}
	raw2, _ := os.ReadFile(path)
	if !bytes.Equal(raw, raw2) {
		t.Error("seed file was rewritten on restart")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestSeedFileReplacesBadContent(t *testing.T) {
	t.Parallel()
	good := hex.EncodeToString(seedOf(9))
	cases := map[string]string{
		"empty":     "",
		"short":     good[:20],
		"too long":  good + "00",
		"not hex":   strings.Repeat("zz", SeedSize),
		"garbage":   "\x00\x01\x02binary",
		"odd count": good[:63],
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "seed")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			p := Load(ModeSeeded, path, testLogger(&logs))
			if p == nil || p.Mode != ModeSeeded {
				t.Fatalf("profile = %+v", p)
			}
			if !strings.Contains(logs.String(), "unusable") {
				t.Errorf("no warning logged: %s", logs.String())
			}
			raw, _ := os.ReadFile(path)
			seed, err := parseSeed(raw)
			if err != nil {
				t.Fatalf("seed file not repaired: %v", err)
			}
			if *FromSeed(seed) != *p {
				t.Error("profile does not match the persisted seed")
			}
			if *Load(ModeSeeded, path, nil) != *p {
				t.Error("repaired seed is not stable")
			}
		})
	}
}

func TestUnwritableLocationUsesEphemeralSeed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing-dir", "seed")
	var logs bytes.Buffer
	log := testLogger(&logs)
	a := loadOrCreateSeed(path, log)
	b := loadOrCreateSeed(path, log)
	if len(a) != SeedSize || len(b) != SeedSize {
		t.Fatalf("seed sizes %d, %d", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Error("ephemeral seeds are identical")
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "cannot persist fingerprint seed") {
		t.Errorf("no warning logged: %s", logs.String())
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("seed file exists")
	}
	if p := Load(ModeSeeded, path, log); p == nil || p.SSH == "" {
		t.Errorf("profile = %+v", p)
	}
}

func TestSeedPathIsADirectory(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	if p := Load(ModeSeeded, t.TempDir(), testLogger(&logs)); p == nil {
		t.Fatal("nil profile")
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("no warning: %s", logs.String())
	}
}

func TestEmptyPathIsEphemeral(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	if p := Load(ModeSeeded, "", testLogger(&logs)); p == nil {
		t.Fatal("nil profile")
	}
	if !strings.Contains(logs.String(), "ephemeral") {
		t.Errorf("no warning: %s", logs.String())
	}
}
