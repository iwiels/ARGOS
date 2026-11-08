package practicetarget

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func get(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func request(t *testing.T, method, url, body string, headers map[string]string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("cannot build %s %s: %v", method, url, err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func TestSQLiBooleanDifferential(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	baseline, body := get(t, srv, "/search?q=1")
	if baseline != http.StatusOK || !strings.Contains(body, "1 resultado") {
		t.Fatalf("baseline: got %d %q", baseline, body)
	}

	// tautology must match the baseline page (same status/body)
	truth, truthBody := get(t, srv, "/search?q=1%27%20AND%20%271%27=%271")
	if truth != http.StatusOK || truthBody != body {
		t.Fatalf("tautology should match baseline: got %d %q, want %d %q", truth, truthBody, baseline, body)
	}

	// contradiction must differ from the baseline
	contra, contraBody := get(t, srv, "/search?q=1%27%20AND%20%271%27=%272")
	if contra != http.StatusOK || contraBody == body {
		t.Fatalf("contradiction should differ from baseline: got %d %q", contra, contraBody)
	}

	// bare quote triggers a SQL error marker
	code, errBody := get(t, srv, "/search?q=%27")
	if code != http.StatusInternalServerError || !strings.Contains(strings.ToLower(errBody), "sql") {
		t.Fatalf("bare quote should 500 with SQL marker: got %d %q", code, errBody)
	}
}

func TestNumericSQLi(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	base, body := get(t, srv, "/item?id=1")
	truth, truthBody := get(t, srv, "/item?id=1%27%20AND%20%271%27=%271")
	_, contraBody := get(t, srv, "/item?id=1%27%20AND%20%271%27=%272")

	if base != 200 || truth != 200 || truthBody != body || contraBody == body {
		t.Fatalf("numeric SQLi differential broken: base=%d truth=%d truthEq=%v contraDiff=%v",
			base, truth, truthBody == body, contraBody != body)
	}
}

func TestReflectedXSS(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	payload := `<script>alert(1)</script>`
	code, body := get(t, srv, "/profile?user="+strings.ReplaceAll(payload, " ", "%20"))
	if code != http.StatusOK || !strings.Contains(body, payload) {
		t.Fatalf("expected unescaped reflection of %q, got %d %q", payload, code, body)
	}
}

func TestHiddenRoutes(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	adminCode, _ := get(t, srv, "/admin/")
	if adminCode != http.StatusOK {
		t.Fatalf("/admin/ should be reachable, got %d", adminCode)
	}
	envCode, envBody := get(t, srv, "/.env")
	if envCode != http.StatusOK || !strings.Contains(envBody, "DB_PASSWORD") {
		t.Fatalf("/.env should expose secrets, got %d %q", envCode, envBody)
	}
	rbCode, rb := get(t, srv, "/robots.txt")
	if rbCode != http.StatusOK || !strings.Contains(rb, "/admin/") {
		t.Fatalf("robots.txt should list /admin/, got %d %q", rbCode, rb)
	}
}

// --- ARG-051: one test per vulnerability class of the ground truth -------

func TestIDORReturnsTheRecordOfAnotherUser(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/api/item/2")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("cannot decode %q: %v", body, err)
	}
	// The handler answers with the record of the owner of the id without
	// comparing it with the session of the caller.
	if doc["owner"] != "user-2" || !strings.Contains(fmt.Sprint(doc["email"]), "user-2@") {
		t.Fatalf("expected the record of user-2, got %v", doc)
	}
}

func TestJWTIsSignedWithAlgNoneAndWithoutClaims(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp := request(t, http.MethodGet, srv.URL+"/api/token", "", nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var doc map[string]string
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("cannot decode %q: %v", body, err)
	}
	token := doc["access_token"]
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a JWS compact serialization, got %q", token)
	}
	if parts[2] != "" {
		t.Fatalf("expected an empty signature segment, got %q", parts[2])
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("cannot decode the header: %v", err)
	}
	if !strings.Contains(string(rawHeader), `"alg":"none"`) {
		t.Fatalf("expected alg none, got %q", rawHeader)
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("cannot decode the claims: %v", err)
	}
	for _, forbidden := range []string{`"exp"`, `"aud"`, `"iss"`} {
		if strings.Contains(string(rawClaims), forbidden) {
			t.Fatalf("the claims should not carry %s: %q", forbidden, rawClaims)
		}
	}
	// The token also travels in a response header.
	if !strings.Contains(resp.Header.Get("Authorization"), token) {
		t.Fatalf("the Authorization header should carry the token, got %q", resp.Header.Get("Authorization"))
	}
}

func TestTransferHasNoCSRFProtection(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	// A cross origin POST is accepted: no token, no Origin validation.
	resp := request(t, http.MethodPost, srv.URL+"/api/transfer", "amount=100",
		map[string]string{"Origin": "https://evil.example"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the transfer should be accepted, got %d", resp.StatusCode)
	}
}

func TestCORSAllowsAnyOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp := request(t, http.MethodGet, srv.URL+"/api/cors", "", nil)
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected a wildcard origin, got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected the credentials to be allowed, got %q", got)
	}
}

func TestFetchIsAServerSideRequest(t *testing.T) {
	// The internal service the target is tricked into fetching.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "internal-secret-document")
	}))
	defer internal.Close()

	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/fetch?url="+internal.URL)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if !strings.Contains(body, "internal-secret-document") {
		t.Fatalf("the target should have fetched the document, got %q", body)
	}
}

func TestFetchLeaksTheInternalAddressOnFailure(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/fetch?url=http://127.0.0.1:1/")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if !strings.Contains(body, "127.0.0.1") {
		t.Fatalf("the failure should name the internal address, got %q", body)
	}
}

func TestXMLParserResolvesExternalEntities(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	payload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	resp := request(t, http.MethodPost, srv.URL+"/api/xml", payload, nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "root:x:0:0") {
		t.Fatalf("the external entity should have been resolved, got %q", body)
	}
}

func TestRenderEvaluatesTheTemplateExpression(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/render?tpl=%7B%7B7*7%7D%7D")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if !strings.Contains(body, "49") {
		t.Fatalf("the expression should have been evaluated, got %q", body)
	}
	if strings.Contains(body, "{{7*7}}") {
		t.Fatalf("the payload should not be echoed back, got %q", body)
	}

	// The baseline value must not produce a differential by itself.
	_, baseline := get(t, srv, "/render?tpl=argos-ssti-baseline")
	if strings.Contains(baseline, "49") {
		t.Fatalf("the baseline must not contain the result, got %q", baseline)
	}
}

func TestRenderEvaluatesEveryEngineSpelling(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	cases := map[string]string{
		"{{7*7}}": "49",
		"${7*7}":  "49",
		"<%= 7*7 %>": "49",
		"#{7*7}":    "49",
		// 7 * '7' repeats the string seven times, like Python does. The
		// web.ssti probe expects nine sevens for this payload, so that
		// probe can never be confirmed; the four arithmetic probes above
		// are the ones that detect the vector.
		"{{7*'7'}}": "7777777",
	}
	for payload, expected := range cases {
		code, body := get(t, srv, "/render?tpl="+urlEscape(payload))
		if code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", payload, code)
		}
		if !strings.Contains(body, expected) {
			t.Fatalf("%s: expected %q in the body, got %q", payload, expected, body)
		}
	}
}

func urlEscape(value string) string {
	return url.QueryEscape(value)
}

func TestRedirectAcceptsAnyDestination(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(srv.URL + "/redirect?u=https://evil.example/phish")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://evil.example/phish" {
		t.Fatalf("expected the destination to be honoured, got %q", got)
	}
}

func TestDownloadEscapesTheBaseDirectory(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/download?file=../../../../etc/passwd")
	if code != http.StatusOK {
		t.Fatalf("expected the traversal to succeed, got %d", code)
	}
	if !strings.Contains(body, "root:x:0:0") {
		t.Fatalf("expected the content of /etc/passwd, got %q", body)
	}
}

func TestPingRunsTheInjectedCommand(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	separator := ";"
	if runtimeIsWindows() {
		separator = "&"
	}
	host := "127.0.0.1" + separator + "echo ARGOS-INJECTED"
	code, body := get(t, srv, "/ping?host="+urlEscape(host))
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if !strings.Contains(body, "ARGOS-INJECTED") {
		t.Fatalf("the injected command should have run, got %q", body)
	}
}

func runtimeIsWindows() bool {
	return runtime.GOOS == "windows"
}

func TestDeserializeExecutesTheGadget(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	payload := `O:8:"Evil":1:{s:3:"cmd";s:20:"echo ARGOS-GADGET";}`
	resp := request(t, http.MethodPost, srv.URL+"/api/deserialize", payload, nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%q)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "ARGOS-GADGET") {
		t.Fatalf("the gadget should have run, got %q", body)
	}
}

func TestGraphQLIntrospectionIsOpen(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	query := `{"query":"query IntrospectionQuery { __schema { queryType { name } types { name kind fields { name type { name kind } } } } }"}`
	resp := request(t, http.MethodPost, srv.URL+"/graphql", query, nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("cannot decode %q: %v", body, err)
	}
	data, _ := doc["data"].(map[string]any)
	schema, _ := data["__schema"].(map[string]any)
	if schema == nil {
		t.Fatalf("the introspection should answer with the schema, got %q", body)
	}
	types, _ := schema["types"].([]any)
	if len(types) == 0 {
		t.Fatalf("the schema should expose the types, got %q", body)
	}
}

func TestGraphQLAcceptsBatchedOperations(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	body := `[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]`
	resp := request(t, http.MethodPost, srv.URL+"/graphql", body, nil)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var answers []any
	if err := json.Unmarshal(raw, &answers); err != nil {
		t.Fatalf("cannot decode %q: %v", raw, err)
	}
	if len(answers) != 3 {
		t.Fatalf("expected three answers, got %d (%q)", len(answers), raw)
	}
}

func TestFrontProxySwallowsTheAmbiguousFraming(t *testing.T) {
	backend := httptest.NewServer(Handler())
	defer backend.Close()

	proxy, err := NewFrontProxy(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// A normal request is proxied and the answer carries the fingerprint of
	// the intermediary.
	resp, err := http.Get(proxy.URL() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Via") == "" {
		t.Fatalf("the proxy should announce itself, got %v", resp.Header)
	}

	// An ambiguous request (Content-Length + Transfer-Encoding) never gets
	// an answer: the two parsers disagree.
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("the ambiguous request should not be answered, got %q", string(buf))
	}
}

func TestCouponRaceConditionRedeemsTwice(t *testing.T) {
	couponUsed.Store(false)
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i := range statuses {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			resp, err := http.Post(srv.URL+"/api/coupon", "application/json", strings.NewReader("{}"))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			statuses[index] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	accepted := 0
	for _, status := range statuses {
		if status == http.StatusOK {
			accepted++
		}
	}
	if accepted < 2 {
		t.Fatalf("the coupon should have been redeemed twice, got %v", statuses)
	}
}

func TestLoginTimingTellsWhetherTheUserExists(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	start := time.Now()
	get(t, srv, "/api/login?user=admin")
	existing := time.Since(start)

	start = time.Now()
	get(t, srv, "/api/login?user=ghost")
	unknown := time.Since(start)

	if existing < unknown+100*time.Millisecond {
		t.Fatalf("the timing should differ: existing=%s unknown=%s", existing, unknown)
	}
}

func TestLoginHasNoRateLimit(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	for i := 0; i < 25; i++ {
		resp := request(t, http.MethodPost, srv.URL+"/api/login", "user=admin", nil)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("the login endpoint should not throttle, got 429 on attempt %d", i+1)
		}
	}
}

func TestGitRepositoryIsExposed(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/.git/")
	if code != http.StatusOK {
		t.Fatalf("the git directory should be listed, got %d", code)
	}
	code, body = get(t, srv, "/.git/HEAD")
	if code != http.StatusOK || !strings.Contains(body, "refs/heads/main") {
		t.Fatalf("the HEAD file should be readable, got %d %q", code, body)
	}
	code, body = get(t, srv, "/.git/config")
	if code != http.StatusOK {
		t.Fatalf("the git config should be readable, got %d", code)
	}
	if !strings.Contains(body, "ghp_") {
		t.Fatalf("the git config should carry the token, got %q", body)
	}
}

func TestJavaScriptBundleCarriesTheAPIKey(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/static/app.js")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if !strings.Contains(body, "AKIA") {
		t.Fatalf("the bundle should carry the key, got %q", body)
	}
}

func TestSessionCookieHasNoSecurityFlags(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp := request(t, http.MethodPost, srv.URL+"/login", "username=admin&password=x", nil)
	defer resp.Body.Close()
	raw := resp.Header.Get("Set-Cookie")
	if raw == "" {
		t.Fatal("the login should set a cookie")
	}
	lower := strings.ToLower(raw)
	for _, forbidden := range []string{"secure", "httponly", "samesite"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("the cookie should not carry %s: %q", forbidden, raw)
		}
	}
}

func TestDataEndpointAcceptsEveryVerb(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		resp := request(t, method, srv.URL+"/api/data", "", nil)
		resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed {
			t.Fatalf("%s should have been accepted, got 405", method)
		}
	}
}

func TestDebugVarsExposesTheSecrets(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, body := get(t, srv, "/debug/vars")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if !strings.Contains(body, "AWS_ACCESS_KEY_ID") || !strings.Contains(body, "DB_PASSWORD") {
		t.Fatalf("the debug endpoint should expose the configuration, got %q", body)
	}
}

func TestSecurityTxtIsMissing(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, _ := get(t, srv, "/security.txt")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", code)
	}
}

func TestDanglingSubdomainAnswers(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = danglingHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "NoSuchBucket") {
		t.Fatalf("the dangling bucket should answer, got %d %q", resp.StatusCode, body)
	}
}

func TestCacheableResponseHasNoVary(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp := request(t, http.MethodGet, srv.URL+"/api/cache", "",
		map[string]string{"X-Forwarded-Host": "victim.example"})
	defer resp.Body.Close()
	if resp.Header.Get("Vary") != "" {
		t.Fatalf("the cached response should not declare Vary, got %q", resp.Header.Get("Vary"))
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "public") {
		t.Fatalf("the response should be cacheable, got %q", resp.Header.Get("Cache-Control"))
	}
}

func TestUnicodePathNormalizationBypass(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	code, _ := get(t, srv, "/unicode/admin")
	if code != http.StatusForbidden {
		t.Fatalf("the plain spelling should be blocked, got %d", code)
	}

	// The fullwidth spelling of "admin" slips through the edge policy and
	// the backend resolves it.
	fullwidth := "%EF%BD%81%EF%BD%84%EF%BD%8D%EF%BD%89%EF%BD%8E"
	code, body := get(t, srv, "/unicode/"+fullwidth)
	if code != http.StatusOK {
		t.Fatalf("the fullwidth spelling should reach the admin resource, got %d", code)
	}
	if !strings.Contains(body, "administraci") {
		t.Fatalf("expected the admin resource, got %q", body)
	}
}
