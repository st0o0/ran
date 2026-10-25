package trap

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/fingerprint"
)

// httpFixtureSet maps an exact request path to a static response. Operator
// entries replace built-in ones with the same path. It is built once at startup
// and only read afterwards, so handlers need no lock.
type httpFixtureSet map[string]config.HTTPFixture

func newHTTPFixtureSet(operator []config.HTTPFixture, web fingerprint.HTTP) httpFixtureSet {
	builtin := builtinHTTPFixtures(web)
	set := make(httpFixtureSet, len(builtin)+len(operator))
	for _, fx := range builtin {
		set[fx.Path] = fx
	}
	for _, fx := range operator {
		set[fx.Path] = fx
	}
	return set
}

// serve writes the fixture for r and reports whether it did. Only GET and HEAD
// are answered; every other method keeps the login page behavior. The response is
// built from the fixture alone, never from the request.
func (s httpFixtureSet) serve(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	fx, ok := s[r.URL.Path]
	if !ok {
		return false
	}
	h := w.Header()
	// The login page defaults do not fit a product fixture; it sets its own.
	h.Del("X-Powered-By")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	for k, v := range fx.Headers {
		h.Set(k, v)
	}
	if fx.Status != http.StatusNoContent {
		h.Set("Content-Length", strconv.Itoa(len(fx.Body)))
	}
	w.WriteHeader(fx.Status)
	if r.Method == http.MethodGet && fx.Status != http.StatusNoContent {
		_, _ = w.Write([]byte(fx.Body))
	}
	return true
}

const (
	textCT = "text/plain; charset=utf-8"
	htmlCT = "text/html; charset=UTF-8"
)

// builtinHTTPFixtures is a small set of static answers for the files scanners ask
// for first. Everything in it is invented: no real address, host name or secret.
func builtinHTTPFixtures(web fingerprint.HTTP) []config.HTTPFixture {
	phpServerAPI := "Apache 2.0 Handler"
	if web.StatusServer == "" {
		phpServerAPI = "FPM/FastCGI"
	}
	fixtures := []config.HTTPFixture{
		{Path: "/.git/HEAD", Status: 200, Headers: map[string]string{"Content-Type": textCT},
			Body: "ref: refs/heads/main\n"},
		{Path: "/.git/config", Status: 200, Headers: map[string]string{"Content-Type": textCT},
			Body: "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n" +
				"[remote \"origin\"]\n\turl = https://git.example.com/acme/webapp.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n" +
				"[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"},
		{Path: "/.env", Status: 200, Headers: map[string]string{"Content-Type": textCT},
			Body: "APP_NAME=webapp\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
				"DB_CONNECTION=mysql\nDB_HOST=db\nDB_PORT=3306\nDB_DATABASE=webapp\nDB_USERNAME=webapp\nDB_PASSWORD=changeme\n"},
		{Path: "/actuator/health", Status: 200, Headers: map[string]string{"Content-Type": "application/vnd.spring-boot.actuator.v3+json"},
			Body: `{"status":"UP"}`},
		{Path: "/actuator/env", Status: 200, Headers: map[string]string{"Content-Type": "application/vnd.spring-boot.actuator.v3+json"},
			Body: `{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties","properties":{"java.version":{"value":"17.0.9"},"os.name":{"value":"Linux"}}}]}`},
		{Path: "/server-status", Status: 200, Headers: map[string]string{"Content-Type": htmlCT},
			Body: "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n<html><head><title>Apache Status</title></head><body>\n" +
				"<h1>Apache Server Status for localhost</h1>\n<dl><dt>Server Version: " + web.StatusServer + "</dt>\n" +
				"<dt>Server uptime:  3 days 4 hours 12 minutes 9 seconds</dt>\n" +
				"<dt>1 requests currently being processed, 9 idle workers</dt></dl></body></html>\n"},
		{Path: "/phpinfo.php", Status: 200, Headers: map[string]string{"Content-Type": htmlCT, "X-Powered-By": web.PoweredBy()},
			Body: "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body><div class=\"center\">\n" +
				"<table><tr class=\"h\"><td><h1 class=\"p\">PHP Version " + web.PHPInfoVersion() + "</h1></td></tr></table>\n" +
				"<table><tr><td class=\"e\">System </td><td class=\"v\">Linux webapp " + web.KernelRelease() + " x86_64 </td></tr>\n" +
				"<tr><td class=\"e\">Server API </td><td class=\"v\">" + phpServerAPI + " </td></tr></table></div></body></html>\n"},
		{Path: "/wp-json/", Status: 200, Headers: map[string]string{"Content-Type": "application/json; charset=UTF-8", "X-Robots-Tag": "noindex"},
			Body: `{"name":"Site","description":"Just another WordPress site","gmt_offset":"0","timezone_string":"","namespaces":["oembed/1.0","wp/v2"],"authentication":[],"routes":{}}`},
		{Path: "/robots.txt", Status: 200, Headers: map[string]string{"Content-Type": textCT},
			Body: "User-agent: *\nDisallow: /admin\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"},
		{Path: "/sitemap.xml", Status: 200, Headers: map[string]string{"Content-Type": "application/xml; charset=UTF-8"},
			Body: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"></urlset>\n"},
		{Path: "/.well-known/security.txt", Status: 200, Headers: map[string]string{"Content-Type": textCT},
			Body: "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\nPreferred-Languages: en\n"},
	}
	if web.StatusServer == "" {
		// Servers without mod_status answer /server-status with the login page.
		fixtures = slices.DeleteFunc(fixtures, func(fx config.HTTPFixture) bool { return fx.Path == "/server-status" })
	}
	return fixtures
}
