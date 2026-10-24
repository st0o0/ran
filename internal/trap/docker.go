package trap

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// Limits for what is taken from a Docker create or exec body.
const (
	maxDockerCmdItems = 64
	maxDockerCmdBytes = 1024
	// maxDockerImageBytes keeps a long image name from crowding the command out
	// of the (bounded) command meta.
	maxDockerImageBytes = 64
)

// DockerTrap is a stub of the Docker Engine API. It reuses the HTTP trap for
// listening, per-connection sessions, limits and shutdown, and only swaps the
// request handler.
type DockerTrap struct {
	*HTTPTrap
}

func NewDocker(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *Limiter, alerter Reporter) *DockerTrap {
	t := &DockerTrap{HTTPTrap: newHTTPTrap("docker", cfg, logger, m, limiter, alerter)}
	t.setHandler(t.handle)
	return t
}

var dockerVersionPrefix = regexp.MustCompile(`^/v[0-9]{1,3}\.[0-9]{1,3}`)

// dockerRoute returns the cleaned request path without the API version prefix.
func dockerRoute(p string) string {
	if len(p) > maxHTTPPath {
		return "/"
	}
	p = path.Clean("/" + p)
	if loc := dockerVersionPrefix.FindStringIndex(p); loc != nil && (loc[1] == len(p) || p[loc[1]] == '/') {
		p = "/" + strings.TrimPrefix(p[loc[1]:], "/")
	}
	return p
}

func isDockerExec(route string) bool {
	rest, ok := strings.CutPrefix(route, "/containers/")
	if !ok {
		return false
	}
	id, tail, ok := strings.Cut(rest, "/")
	return ok && id != "" && len(id) <= 128 && tail == "exec"
}

// dockerKnownPrefixes are the API areas that answer 403 instead of 404 to a
// state-changing request.
var dockerKnownPrefixes = []string{"/containers/", "/images/", "/exec/", "/build", "/networks/", "/volumes/", "/services/", "/swarm", "/plugins/", "/commit", "/auth"}

func dockerKnown(route string) bool {
	for _, p := range dockerKnownPrefixes {
		if strings.HasPrefix(route, p) {
			return true
		}
	}
	return false
}

const (
	dockerVersionJSON = `{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"24.0.7","Details":{"ApiVersion":"1.43","Arch":"amd64","BuildTime":"2023-10-26T09:08:20.000000000+00:00","Experimental":"false","GitCommit":"311b9ff","GoVersion":"go1.20.10","KernelVersion":"5.15.0-91-generic","MinAPIVersion":"1.12","Os":"linux"}}],"Version":"24.0.7","ApiVersion":"1.43","MinAPIVersion":"1.12","GitCommit":"311b9ff","GoVersion":"go1.20.10","Os":"linux","Arch":"amd64","KernelVersion":"5.15.0-91-generic","BuildTime":"2023-10-26T09:08:20.000000000+00:00"}`
	dockerInfoJSON    = `{"ID":"7b1a3f0e-6c2d-4c1b-9d52-2f0c1a5e9b10","Containers":0,"ContainersRunning":0,"ContainersPaused":0,"ContainersStopped":0,"Images":0,"Driver":"overlay2","OperatingSystem":"Ubuntu 22.04.3 LTS","OSType":"linux","Architecture":"x86_64","NCPU":4,"MemTotal":8335593472,"ServerVersion":"24.0.7","Name":"docker-host","KernelVersion":"5.15.0-91-generic"}`
)

func (t *DockerTrap) handle(w http.ResponseWriter, r *http.Request) {
	req, ok := newStubRequest(w, r)
	if !ok {
		return
	}
	sess := req.sess
	route := dockerRoute(r.URL.Path)

	h := w.Header()
	h.Set("Server", "Docker/24.0.7 (linux)")
	h.Set("Api-Version", "1.43")
	h.Set("Ostype", "linux")
	h.Set("Docker-Experimental", "false")

	readOnly := isReadOnlyMethod(r.Method)
	alerted := false

	switch {
	case req.jndi:
		req.command(req.method + " " + req.path)
		alerted = true
	case r.Method == http.MethodPost && route == "/containers/create":
		image, cmd := parseDockerBody(req.body)
		image = truncateRunes(sanitizeHTTPValue(image), maxDockerImageBytes)
		req.meta["image"] = image
		req.command("docker create image=" + image + " cmd=" + cmd)
		alerted = true
	case r.Method == http.MethodPost && isDockerExec(route):
		_, cmd := parseDockerBody(req.body)
		req.command("docker exec cmd=" + cmd)
		alerted = true
	case !readOnly:
		// Any other state change (image pull, start, delete, build) is recorded
		// by method and path only; the body is never logged.
		req.command(req.method + " " + req.path)
		alerted = true
	default:
		sess.Log("docker request", req.attrs...)
	}

	if req.bodyLen > 0 && !alerted {
		// Only the size counts; no body sample is kept for a read-only request.
		sess.LogPayloadSize("http_body", req.bodyLen, slog.String("path", req.path), slog.Int("bytes", req.bodyLen))
		alerted = true
	}
	if alerted {
		sess.Alert(r.Context(), req.meta)
	}

	switch {
	case !readOnly:
		if dockerKnown(route) {
			writeStubMessage(w, http.StatusForbidden, "authorization denied by plugin: container operations are not permitted")
			return
		}
		writeStubMessage(w, http.StatusNotFound, "page not found")
	case route == "/_ping":
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Builder-Version", "2")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("OK"))
		}
	case route == "/version":
		writeStubJSON(w, http.StatusOK, dockerVersionJSON)
	case route == "/info":
		writeStubJSON(w, http.StatusOK, dockerInfoJSON)
	case route == "/containers/json", route == "/images/json":
		writeStubJSON(w, http.StatusOK, "[]")
	default:
		writeStubMessage(w, http.StatusNotFound, "page not found")
	}
}

// parseDockerBody extracts the image and the command line from a container
// create or exec body. Entrypoint and Cmd may be a string or a list of strings.
// The body is at most maxHTTPBody bytes; a body that is not valid JSON yields
// empty values. The result is bounded by maxDockerCmdBytes plus one item.
func parseDockerBody(body []byte) (image, cmd string) {
	var v struct {
		Image      string `json:"Image"`
		Entrypoint any    `json:"Entrypoint"`
		Cmd        any    `json:"Cmd"`
	}
	if len(body) > maxHTTPBody || json.Unmarshal(body, &v) != nil {
		return "", ""
	}
	parts := append(dockerWords(v.Entrypoint), dockerWords(v.Cmd)...)
	return truncateRunes(v.Image, maxHTTPValue), joinStrings(parts, maxDockerCmdItems, maxDockerCmdBytes)
}

func dockerWords(x any) []string {
	switch v := x.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, min(len(v), maxDockerCmdItems))
		for _, e := range v {
			if len(out) >= maxDockerCmdItems {
				break
			}
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// truncateRunes cuts s to at most n bytes at a rune boundary, so valid UTF-8
// stays valid.
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// isReadOnlyMethod reports whether a method never changes state. OPTIONS is
// included because crawlers and CORS preflights send it. State-changing methods
// (POST, PUT, PATCH, DELETE) and the unusual ones (PROPFIND, CONNECT, TRACE and
// anything else) are not read-only and count as an attack.
func isReadOnlyMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}
