package fingerprint

import (
	"bytes"
	"fmt"
	"testing"
)

// goldenSeeds are fixed seeds whose full profile is pinned below.
func goldenSeeds() map[string][]byte {
	return map[string][]byte{
		"zero": make([]byte, SeedSize),
		"ff":   bytes.Repeat([]byte{0xff}, SeedSize),
		"42":   bytes.Repeat([]byte{0x42}, SeedSize),
		"seq": func() []byte {
			b := make([]byte, SeedSize)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
	}
}

// TestGoldenSelection pins the entry every table selects for fixed seeds. A
// change here means existing instances show different banners after an upgrade:
// a reordered table, a renamed key, an edited entry or a changed index function.
// Update the expectations only on purpose and note the upgrade effect.
func TestGoldenSelection(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"zero": "ssh=\"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\" mysql=\"5.7.42-0ubuntu0.18.04.1\" http={Server:Apache/2.4.57 (Debian) PHP:8.2.7 StatusServer:Apache/2.4.57 (Debian) Kernel:6.1.0-10-amd64 PHPPackage:8.2.7-1~deb12u1} smtp={Host:mx.example.org Software:ESMTP Postfix (Ubuntu)} es={Version:7.17.22 ClusterName:logging NodeName:elasticsearch-0 Build:{Type:docker Hash:38e9ca2e81304a821c50862dafab089ca863944b Date:2024-06-06T07:35:17.140964585Z Lucene:8.11.3 MinWire:6.8.0 MinIndex:6.0.0-beta1}}",
		"ff":   "ssh=\"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\" mysql=\"5.7.44\" http={Server:Apache/2.4.57 (Debian) PHP:8.2.7 StatusServer:Apache/2.4.57 (Debian) Kernel:6.1.0-10-amd64 PHPPackage:8.2.7-1~deb12u1} smtp={Host:mail01.example.net Software:ESMTP Postfix (Ubuntu)} es={Version:7.10.2 ClusterName:elasticsearch NodeName:node-1 Build:{Type:docker Hash:747e1cc71def077253878a59143c1f785afa92b9 Date:2021-01-13T00:42:12.435326Z Lucene:8.7.0 MinWire:6.8.0 MinIndex:6.0.0-beta1}}",
		"42":   "ssh=\"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\" mysql=\"8.0.37\" http={Server:nginx/1.22.1 PHP:8.2.26 StatusServer: Kernel:6.1.0-27-amd64 PHPPackage:8.2.26-1~deb12u1} smtp={Host:mail.example.com Software:ESMTP Postfix (Ubuntu)} es={Version:7.17.22 ClusterName:docker-cluster NodeName:es01 Build:{Type:docker Hash:38e9ca2e81304a821c50862dafab089ca863944b Date:2024-06-06T07:35:17.140964585Z Lucene:8.11.3 MinWire:6.8.0 MinIndex:6.0.0-beta1}}",
		"seq":  "ssh=\"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\" mysql=\"8.0.40-0ubuntu0.24.04.1\" http={Server:nginx/1.18.0 (Ubuntu) PHP:8.1.2 StatusServer: Kernel:5.15.0-122-generic PHPPackage:8.1.2-1ubuntu2.18} smtp={Host:mx1.example.net Software:ESMTP Postfix (Ubuntu)} es={Version:7.17.22 ClusterName:docker-cluster NodeName:es01 Build:{Type:docker Hash:38e9ca2e81304a821c50862dafab089ca863944b Date:2024-06-06T07:35:17.140964585Z Lucene:8.11.3 MinWire:6.8.0 MinIndex:6.0.0-beta1}}",
	}
	for name, seed := range goldenSeeds() {
		if got := goldenString(FromSeed(seed)); got != want[name] {
			t.Errorf("seed %s:\n got  %s\n want %s", name, got, want[name])
		}
	}
}

func goldenString(p *Profile) string {
	return fmt.Sprintf("ssh=%q mysql=%q http=%+v smtp=%+v es=%+v", p.SSH, p.MySQL, p.HTTP, p.SMTP, p.Elasticsearch)
}

// TestSelectionDependsOnKeyNotPosition: reordering a table does not move the
// choice, and appending an entry keeps most choices.
func TestSelectionDependsOnKeyNotPosition(t *testing.T) {
	t.Parallel()
	rev := make([]string, len(sshTable))
	for i, v := range sshTable {
		rev[len(sshTable)-1-i] = v
	}
	moved := 0
	for i := range 200 {
		seed := bytes.Repeat([]byte{byte(i)}, SeedSize)
		a := pick(seed, "ssh", sshTable, ident)
		if b := pick(seed, "ssh", rev, ident); a != b {
			t.Fatalf("seed %d: reorder moved %q to %q", i, a, b)
		}
		if c := pick(seed, "ssh", append(append([]string(nil), sshTable...), "SSH-2.0-OpenSSH_9.9p1 extra"), ident); c != a {
			moved++
		}
	}
	// About 1/7 of the instances may take the new entry; far from all.
	if moved > 60 {
		t.Errorf("appending moved %d of 200 seeds", moved)
	}
}
