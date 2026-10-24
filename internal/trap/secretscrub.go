package trap

import (
	"regexp"
	"strings"
)

// secretNameParts mark names (argument keys, variable names, flags) whose value is a
// credential. Matching is a case-insensitive substring match, so it errs on the side
// of hiding too much.
var secretNameParts = []string{
	"password", "passwd", "pwd", "passphrase", "secret", "token",
	"api_key", "api-key", "apikey", "access_key", "access-key",
	"auth", "authorization", "bearer", "cookie", "session", "jwt",
	"credential", "private_key", "private-key",
}

// secretName reports whether name looks like the name of a credential.
func secretName(name string) bool {
	name = strings.ToLower(name)
	for _, p := range secretNameParts {
		if strings.Contains(name, p) {
			return true
		}
	}
	return false
}

var (
	secretPartsAlt = func() string {
		q := make([]string, len(secretNameParts))
		for i, p := range secretNameParts {
			q[i] = regexp.QuoteMeta(p)
		}
		return strings.Join(q, "|")
	}()
	// Cookie header values may hold spaces, so everything up to a quote is hidden.
	cookieRe = regexp.MustCompile(`(?i)\b((?:set-)?cookie)(["']?[ \t]*:[ \t]*)[^'"\r\n]+`)
	// Authorization headers: the optional scheme and the credential are hidden.
	authHeaderRe = regexp.MustCompile(`(?i)\b(proxy-authorization|authorization)(["']?[ \t]*[:=][ \t]*)(?:(?:bearer|basic|digest|token)[ \t]+)?(?:"[^"]*"|'[^']*'|[^\s'"]+)`)
	// A bearer token anywhere in the text.
	bearerRe = regexp.MustCompile(`(?i)\b(bearer)([ \t]+)[^\s'"]+`)
	// Credentials in a URL: scheme://user:password@host.
	urlCredRe = regexp.MustCompile(`(://)[^/\s:@'"]+:[^@\s/'"]+@`)
	// A flag whose name is secret-like followed by its value: --password hunter2.
	flagRe = regexp.MustCompile(`(?i)(--?[a-z0-9_-]*(?:` + secretPartsAlt + `)[a-z0-9_-]*)([ \t]+)([^\s-][^\s]*)`)
	// NAME=value, NAME: value and "name":"value" where the name is secret-like.
	keyValueRe = regexp.MustCompile(`(?i)([a-z0-9_.-]*(?:` + secretPartsAlt + `)[a-z0-9_.-]*)(["']?[ \t]*[=:][ \t]*)("[^"]*"|'[^']*'|[^\s'",;&|}]+)`)
)

// scrubSecrets hides values that look like credentials in a command string or an
// argument value: cookie and authorization headers, bearer tokens, URL userinfo,
// secret-like flags and KEY=value pairs. It is a best effort: a secret that has no
// recognizable name or shape is not found. The result keeps the structure of the
// text so it stays useful for classification.
func scrubSecrets(s string) string {
	if s == "" {
		return s
	}
	s = cookieRe.ReplaceAllString(s, "${1}${2}***")
	s = authHeaderRe.ReplaceAllString(s, "${1}${2}***")
	s = bearerRe.ReplaceAllString(s, "${1}${2}***")
	s = urlCredRe.ReplaceAllString(s, "${1}***@")
	s = flagRe.ReplaceAllString(s, "${1}${2}***")
	s = keyValueRe.ReplaceAllString(s, "${1}${2}***")
	return s
}

// logScrubSecrets is scrubSecrets for log output: RAN_LOG_PASSWORDS=on keeps the
// text, as it does for the other redaction helpers.
func logScrubSecrets(s string) string {
	if passwordMode.Load() == passwordsOn {
		return s
	}
	return scrubSecrets(s)
}

// metaCommandText returns a command string for alert meta. Meta goes to CrowdSec,
// so secrets are scrubbed whatever RAN_LOG_PASSWORDS says. The text is sanitized and
// bounded before and after the scrub.
func metaCommandText(raw string) string {
	return sanitizeHTTPValue(scrubSecrets(sanitizeHTTPValue(raw)))
}

// logCommandText returns a command string for the log: sanitized, bounded and
// scrubbed according to RAN_LOG_PASSWORDS.
func logCommandText(raw string) string {
	return sanitizeHTTPValue(logScrubSecrets(sanitizeHTTPValue(raw)))
}
