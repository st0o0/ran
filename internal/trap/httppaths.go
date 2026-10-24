package trap

import (
	"net/url"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxHTTPValue bounds every request value that is logged or sent as alert meta.
const maxHTTPValue = 256

// maxHTTPMatch bounds how much of a path or header value the matchers inspect.
const maxHTTPMatch = 1024

// exploitPathsExact lists lower-case cleaned paths that no legitimate visitor of a
// honeypot asks for: secrets files, VCS metadata, dumps and common web shells.
var exploitPathsExact = map[string]bool{
	"/.env": true, "/.env.local": true, "/.env.production": true, "/.env.dev": true,
	"/.env.bak": true, "/.env.example": true, "/env": true, "/.envrc": true,
	"/.htpasswd": true, "/.htaccess": true, "/.ds_store": true, "/.npmrc": true,
	"/.dockercfg": true, "/.bash_history": true, "/id_rsa": true, "/id_dsa": true,
	"/wp-config.php": true, "/wp-config.php.bak": true, "/wp-config.php.old": true,
	"/wp-config.php~": true, "/wp-config.txt": true, "/configuration.php": true,
	"/config.php": true, "/config.json": true, "/config.yml": true, "/config.yaml": true,
	"/settings.py": true, "/web.config": true, "/appsettings.json": true,
	"/application.properties": true, "/application.yml": true,
	"/backup.sql": true, "/backup.zip": true, "/dump.sql": true, "/database.sql": true,
	"/db.sql": true, "/site.tar.gz": true, "/backup.tar.gz": true,
	"/phpinfo.php": true, "/info.php": true, "/test.php": true, "/shell.php": true,
	"/cmd.php": true, "/c99.php": true, "/r57.php": true, "/wso.php": true,
	"/xmlrpc.php": true, "/server-status": true, "/server-info": true,
	"/login.action": true, "/invoker/jmxinvokerservlet": true,
	"/v2/_catalog": true, "/containers/json": true, "/script": true,
	"/debug/pprof": true, "/_profiler": true, "/telescope": true,
}

// exploitPathPrefixes lists lower-case prefixes of framework admin endpoints,
// metadata directories and well-known exploit targets.
var exploitPathPrefixes = []string{
	"/.git/", "/.svn/", "/.hg/", "/.aws/", "/.ssh/", "/.docker/", "/.kube/", "/.vscode/",
	"/actuator", "/jolokia", "/cgi-bin/", "/cgi/", "/phpmyadmin", "/pma/", "/myadmin",
	"/manager/html", "/host-manager/", "/jmx-console", "/web-console", "/invoker/",
	"/vendor/phpunit/", "/_ignition/", "/_debug/", "/solr/", "/jenkins/script",
	"/scripttext", "/console/", "/h2-console", "/boaform/", "/hnap1",
	"/ecp/", "/owa/auth", "/autodiscover/", "/remote/login", "/+cscoe+/",
	"/api/jsonws/", "/axis2/", "/struts", "/druid/", "/nacos/", "/geoserver/",
	"/wp-content/plugins/", "/wp-json/wp/v2/users",
	"/wp-admin/admin-ajax.php",
	"/bin/", "/etc/", "/proc/", "/mgmt/tm/", "/api/v1/pods", "/api/v1/secrets",
	"/stalker_portal/", "/setup.cgi", "/goform/", "/apply.cgi", "/command.php",
}

// exploitPathSubstrings catch traversal and file read attempts anywhere in the path.
var exploitPathSubstrings = []string{
	"../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self/", "win.ini", "boot.ini",
	"eval-stdin.php", "/.git/", "/.env",
}

func init() {
	// The prefix list is matched against lower-case input.
	for i, p := range exploitPathPrefixes {
		exploitPathPrefixes[i] = strings.ToLower(p)
	}
}

// matchExploitPath reports whether p (a decoded URL path) targets a known exploit
// or recon path. Matching is case-insensitive on the cleaned path and inspects at
// most maxHTTPMatch bytes.
func matchExploitPath(p string) bool {
	if len(p) > maxHTTPMatch {
		p = p[:maxHTTPMatch]
	}
	p = strings.ToLower(p)
	for _, s := range exploitPathSubstrings {
		if strings.Contains(p, s) {
			return true
		}
	}
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	p = path.Clean(p)
	if exploitPathsExact[p] {
		return true
	}
	// Prefix entries without a trailing slash also match the bare directory.
	for _, pre := range exploitPathPrefixes {
		if strings.HasPrefix(p, pre) || p+"/" == pre {
			return true
		}
	}
	return false
}

// matchJNDI reports whether s holds a JNDI lookup string, including the common
// nested obfuscations (`${${lower:j}ndi:`). Input is cut to maxHTTPMatch bytes
// and also checked after percent decoding.
func matchJNDI(s string) bool {
	if len(s) > maxHTTPMatch {
		s = s[:maxHTTPMatch]
	}
	if jndiIn(s) {
		return true
	}
	if strings.ContainsRune(s, '%') {
		if dec, err := url.PathUnescape(s); err == nil && jndiIn(dec) {
			return true
		}
	}
	return false
}

func jndiIn(s string) bool {
	s = strings.ToLower(s)
	if strings.Contains(s, "${jndi:") {
		return true
	}
	return strings.Contains(s, "${${") && strings.Contains(s, "ndi:")
}

// sanitizeHTTPValue cuts s to at most maxHTTPValue bytes at a rune boundary and
// replaces control and format characters with a space.
func sanitizeHTTPValue(s string) string {
	var b strings.Builder
	b.Grow(min(len(s), maxHTTPValue))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1:
			r = '?'
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029:
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > maxHTTPValue {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
