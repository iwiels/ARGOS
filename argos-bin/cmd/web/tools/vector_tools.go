package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

// RegisterVectors registers the eight business-logic web tools.
//
// Linux-first routes the six HTTP-only probes through the isolated scope-gateway
// worker. SSRF and request-smuggling remain unavailable in that profile until
// the runtime provides a target-reachable callback and scoped raw TCP support.
func RegisterVectors(s *mcp.Server, env *Env) {
	RegisterJWT(s, env)
	RegisterSSRF(s, env)
	RegisterCSRF(s, env)
	RegisterGraphQL(s, env)
	RegisterSmuggle(s, env)
	RegisterOAuth(s, env)
	RegisterSSTI(s, env)
	RegisterPromptInjection(s, env)
}

const (
	// maxVectorBodyBytes caps the response body kept in memory per request.
	maxVectorBodyBytes = 1 << 20

	// vectorUserAgent is the benign client identity of every native probe.
	vectorUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// vectorDefaultTimeout is the per-request budget of the native tools when
	// the caller does not ask for a specific one.
	vectorDefaultTimeout = 15 * time.Second

	// vectorMaxTimeout caps the per-request budget a caller may ask for.
	vectorMaxTimeout = 60 * time.Second
)

// vectorResponse is the outcome of one native request.
type vectorResponse struct {
	Status  int
	Headers http.Header
	Body    string
	Elapsed time.Duration
}

// vectorSpec describes the request under test of the injection based tools.
//
// The parameter that carries the attacker controlled value can live in the
// query string or in the body; both are described here so every tool builds
// the same shape of request.
type vectorSpec struct {
	URL         string
	Method      string
	Body        string
	ContentType string
	Param       string
	Surface     string
}

// Surfaces where an injected value can live.
const (
	vectorSurfaceQuery = "query"
	vectorSurfaceBody  = "body"
)

// vectorResult builds the response envelope shared by the native tools.
//
// The native tools do not run a binary, so the envelope carries the engine
// instead of the exit code of a subprocess.
func vectorResult(tool, target string, started time.Time) map[string]interface{} {
	return map[string]interface{}{
		"tool":        tool,
		"target":      target,
		"status":      "completed",
		"duration_ms": time.Since(started).Milliseconds(),
		"engine":      "native",
	}
}

// vectorTimeout resolves the per-request budget of a native tool.
func vectorTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return vectorDefaultTimeout
	}
	budget := time.Duration(seconds) * time.Second
	if budget > vectorMaxTimeout {
		budget = vectorMaxTimeout
	}
	return budget
}

// vectorFetch performs one request against a target.
//
// The client MUST be the scope-bound one (Env.Client): the probe belongs to
// the engagement traffic and has to be pinned, rate limited and audited like
// every other request of the session.
func vectorFetch(ctx context.Context, client *http.Client, method, rawURL string, headers http.Header, body string, timeout time.Duration) (*vectorResponse, error) {
	if client == nil {
		return nil, errors.New("no scope-bound HTTP client available")
	}
	if timeout <= 0 {
		timeout = vectorDefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("cannot build the request: %w", err)
	}
	req.Header.Set("User-Agent", vectorUserAgent)
	req.Header.Set("Accept", "*/*")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if body != "" {
		req.ContentLength = int64(len(body))
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxVectorBodyBytes))
	return &vectorResponse{
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    string(raw),
		Elapsed: time.Since(start),
	}, nil
}

// vectorBuildRequest builds the request under test with the injected value
// written into the parameter slot of the spec.
func vectorBuildRequest(ctx context.Context, spec vectorSpec, value string) (*http.Request, error) {
	method, body, contentType := vectorRequestShape(spec)

	target, err := url.Parse(spec.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("cannot build the request: %w", err)
	}
	req.Header.Set("User-Agent", vectorUserAgent)
	req.Header.Set("Accept", "*/*")
	if body != "" {
		req.Header.Set("Content-Type", contentType)
		req.ContentLength = int64(len(body))
	}
	if spec.Param == "" {
		return req, nil
	}
	if err := vectorWriteParam(req, spec, value, contentType); err != nil {
		return nil, err
	}
	return req, nil
}

// vectorRequestShape resolves the method, the body and the content type of
// the request under test.
func vectorRequestShape(spec vectorSpec) (method, body, contentType string) {
	method = strings.ToUpper(strings.TrimSpace(spec.Method))
	body = spec.Body
	contentType = strings.TrimSpace(spec.ContentType)
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
		if strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[") {
			contentType = "application/json"
		}
	}
	if method == "" {
		if body != "" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	return method, body, contentType
}

// vectorResolveSurface decides where the injected value lives.
//
// The caller can force the surface; when it does not, a parameter that
// appears in the body goes there and everything else goes to the query
// string.
func vectorResolveSurface(spec vectorSpec) string {
	surface := strings.ToLower(strings.TrimSpace(spec.Surface))
	switch surface {
	case vectorSurfaceQuery, vectorSurfaceBody:
		return surface
	}
	if spec.Body != "" && spec.Param != "" && strings.Contains(spec.Body, spec.Param) {
		return vectorSurfaceBody
	}
	return vectorSurfaceQuery
}

// vectorWriteParam writes the injected value into the parameter slot of the
// request, in the query string or in the body.
func vectorWriteParam(req *http.Request, spec vectorSpec, value, contentType string) error {
	surface := vectorResolveSurface(spec)
	switch surface {
	case vectorSurfaceBody:
		if strings.Contains(strings.ToLower(contentType), "json") {
			var doc map[string]any
			if err := json.Unmarshal([]byte(spec.Body), &doc); err != nil {
				return fmt.Errorf("cannot decode the JSON body: %w", err)
			}
			doc[spec.Param] = value
			raw, err := json.Marshal(doc)
			if err != nil {
				return fmt.Errorf("cannot encode the JSON body: %w", err)
			}
			return vectorSetBody(req, string(raw), contentType)
		}
		values, err := url.ParseQuery(spec.Body)
		if err != nil {
			return fmt.Errorf("cannot parse the form body: %w", err)
		}
		values.Set(spec.Param, value)
		return vectorSetBody(req, values.Encode(), contentType)
	default:
		query := req.URL.Query()
		query.Set(spec.Param, value)
		req.URL.RawQuery = query.Encode()
		return nil
	}
}

// vectorSetBody replaces the body of a request.
func vectorSetBody(req *http.Request, body, contentType string) error {
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", contentType)
	return nil
}

// vectorHeader is a small helper to build the header map of a request.
func vectorHeader(pairs map[string]string) http.Header {
	headers := http.Header{}
	for name, value := range pairs {
		headers.Set(name, value)
	}
	return headers
}

// vectorCount returns how many times the needle appears in the haystack.
//
// The comparison is case insensitive: the arithmetic results of the template
// probes are digits, but the surrounding markup is not.
func vectorCount(haystack, needle string) int {
	if needle == "" {
		return 0
	}
	return strings.Count(strings.ToLower(haystack), strings.ToLower(needle))
}

// vectorTruncate shortens a value so the evidence stays inside the contract
// limits without losing the part that matters.
func vectorTruncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "...[truncated]"
}

// scopeGuardFor returns the scope guard of the engagement and the function
// that releases it.
//
// The raw socket probes (request smuggling) cannot use the HTTP client, so
// they dial through the guard itself: that is what keeps the IP-pinning, the
// rate limit and the audit log of the engagement on every connection.
func scopeGuardFor(env *Env) (*scope.ScopeGuard, func(), error) {
	if env == nil {
		return nil, nil, errors.New("no tool environment available")
	}
	if env.Scope != nil {
		return env.Scope, func() {}, nil
	}
	guard, err := scope.New(scope.ScopeConfig{})
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create the scope guard: %w", err)
	}
	return guard, guard.Close, nil
}
