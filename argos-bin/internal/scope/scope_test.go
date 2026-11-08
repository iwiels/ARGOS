package scope

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestScopeGuard_IPAndCIDRMatching(t *testing.T) {
	sg, err := New(ScopeConfig{
		AllowedCIDRs:   []string{"192.168.1.0/24", "10.10.0.5/32"},
		AllowedDomains: []string{"*.target.local", "api.example.com", "https://portal.company.com/"},
		ExcludedHosts:  []string{"192.168.1.254", "internal.target.local"},
		MaxRPS:         50,
	})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()

	// Allowed IP in /24
	if !sg.IsIPAllowed(net.ParseIP("192.168.1.50")) {
		t.Errorf("expected 192.168.1.50 to be allowed")
	}

	// Explicit /32 IP
	if !sg.IsIPAllowed(net.ParseIP("10.10.0.5")) {
		t.Errorf("expected 10.10.0.5 to be allowed")
	}

	// Out of scope IP
	if sg.IsIPAllowed(net.ParseIP("10.10.0.6")) {
		t.Errorf("expected 10.10.0.6 to be blocked")
	}

	// Excluded IP inside allowed CIDR
	if sg.IsIPAllowed(net.ParseIP("192.168.1.254")) {
		t.Errorf("expected 192.168.1.254 to be excluded")
	}

	// Allowed wildcard domain
	if !sg.IsDomainAllowed("app.target.local") {
		t.Errorf("expected app.target.local to be allowed")
	}

	// Exact domain
	if !sg.IsDomainAllowed("api.example.com") {
		t.Errorf("expected api.example.com to be allowed")
	}

	// Normalized URL domain
	if !sg.IsDomainAllowed("portal.company.com") {
		t.Errorf("expected portal.company.com to be allowed from URL config")
	}

	// Subdomain not covered by exact pattern
	if sg.IsDomainAllowed("v2.api.example.com") {
		t.Errorf("expected v2.api.example.com to be blocked")
	}

	// Excluded domain
	if sg.IsDomainAllowed("internal.target.local") {
		t.Errorf("expected internal.target.local to be excluded")
	}
}

func TestScopeGuard_ValidateTargetDirectIP(t *testing.T) {
	sg, err := New(ScopeConfig{
		AllowedCIDRs:  []string{"172.16.0.0/16"},
		ExcludedHosts: []string{"172.16.1.1"},
	})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()

	ctx := context.Background()

	// Allowed IP
	ip, err := sg.ValidateTarget(ctx, "172.16.10.20")
	if err != nil || ip != "172.16.10.20" {
		t.Errorf("expected 172.16.10.20 to be validated, got ip=%s, err=%v", ip, err)
	}

	// Target with URL scheme
	ip, err = sg.ValidateTarget(ctx, "https://172.16.10.20:8443/admin")
	if err != nil || ip != "172.16.10.20" {
		t.Errorf("expected URL target to extract 172.16.10.20, got ip=%s, err=%v", ip, err)
	}

	// Excluded IP
	_, err = sg.ValidateTarget(ctx, "172.16.1.1")
	if !errors.Is(err, ErrOutOfScope) {
		t.Errorf("expected ErrOutOfScope for excluded IP, got %v", err)
	}

	// Blocked out of scope IP
	_, err = sg.ValidateTarget(ctx, "8.8.8.8")
	if !errors.Is(err, ErrOutOfScope) {
		t.Errorf("expected ErrOutOfScope for out of scope IP, got %v", err)
	}
}

func TestScopeGuard_EmptyScopeFailsClosed(t *testing.T) {
	sg, err := New(ScopeConfig{})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()
	sg.SetResolver(fakeResolver{hosts: map[string][]net.IP{
		"public.example.com": {net.ParseIP("203.0.113.10")},
	}})

	if sg.IsIPAllowed(net.ParseIP("203.0.113.10")) {
		t.Fatal("an empty scope must not allow an IP")
	}
	if sg.IsDomainAllowed("public.example.com") {
		t.Fatal("an empty scope must not allow a domain")
	}
	if _, err := sg.ValidateTarget(context.Background(), "public.example.com"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope for an empty scope, got %v", err)
	}
}

func TestScopeGuard_DomainScopeDoesNotAuthorizePrivateResolution(t *testing.T) {
	privateIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.5"), net.ParseIP("169.254.169.254")}
	for _, privateIP := range privateIPs {
		t.Run(privateIP.String(), func(t *testing.T) {
			sg, err := New(ScopeConfig{AllowedDomains: []string{"app.example.com"}})
			if err != nil {
				t.Fatalf("failed to create ScopeGuard: %v", err)
			}
			defer sg.Close()
			sg.SetResolver(fakeResolver{hosts: map[string][]net.IP{"app.example.com": {privateIP}}})

			if _, err := sg.ValidateTarget(context.Background(), "app.example.com"); !errors.Is(err, ErrOutOfScope) {
				t.Fatalf("expected private DNS resolution to be blocked, got %v", err)
			}
			if sg.Allowed("app.example.com") {
				t.Fatal("Allowed must reject a domain resolving to a private address")
			}
		})
	}
}

func TestScopeGuard_PrivateResolutionRequiresExplicitCIDR(t *testing.T) {
	sg, err := New(ScopeConfig{
		AllowedDomains: []string{"app.example.com"},
		AllowedCIDRs:   []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()
	sg.SetResolver(fakeResolver{hosts: map[string][]net.IP{
		"app.example.com": {net.ParseIP("10.0.0.5")},
	}})

	if ip, err := sg.ValidateTarget(context.Background(), "app.example.com"); err != nil || ip != "10.0.0.5" {
		t.Fatalf("expected explicit CIDR to authorize the private target, got ip=%q err=%v", ip, err)
	}
}

func TestScopeGuard_IPPinningAndDialContext(t *testing.T) {
	// Start a local test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ARGOS_SCOPE_OK"))
	}))
	defer server.Close()

	serverHost, serverPort, _ := net.SplitHostPort(server.Listener.Addr().String())

	// Configure scope allowing 127.0.0.0/8
	tmpDir, err := os.MkdirTemp("", "scope_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	sg, err := New(ScopeConfig{
		AllowedCIDRs:   []string{"127.0.0.0/8"},
		AllowedDomains: []string{"localhost"},
		SessionID:      "test-sess-1",
		AuditLogDir:    tmpDir,
		MaxRPS:         100,
	})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()

	client := sg.NewHTTPClient(5 * time.Second)

	// Petición al servidor HTTP local a través del cliente protegido
	reqURL := "http://127.0.0.1:" + serverPort + "/test"
	resp, err := client.Get(reqURL)
	if err != nil {
		t.Fatalf("client.Get(%s) failed: %v", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verificar que el Audit Trail se haya escrito con hashes encadenados
	auditPath := filepath.Join(tmpDir, "audit-test-sess-1.jsonl")
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("audit file not created: %v", err)
	}
	defer file.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
	}

	if len(entries) == 0 {
		t.Errorf("expected at least 1 audit entry, got 0")
	}

	// Verificar encadenamiento de hashes
	var lastHash string
	for i, e := range entries {
		if e.SessionID != "test-sess-1" {
			t.Errorf("entry %d has wrong session_id: %s", i, e.SessionID)
		}
		if e.PrevHash != lastHash {
			t.Errorf("entry %d prev_hash mismatch: expected %q, got %q", i, lastHash, e.PrevHash)
		}
		if e.Hash == "" {
			t.Errorf("entry %d missing hash", i)
		}
		lastHash = e.Hash
	}

	// Intentar conectar a una IP fuera de scope debe fallar de inmediato
	blockedURL := "http://192.0.2.1:" + serverPort + "/blocked"
	_, err = client.Get(blockedURL)
	if err == nil {
		t.Errorf("expected connection to 192.0.2.1 to be blocked by ScopeGuard")
	}
	_ = serverHost
}

func TestScopeGuard_RateLimiterSafeMode(t *testing.T) {
	sg, err := New(ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		MaxRPS:       2,
		SafeMode:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sg.Close()

	ctx := context.Background()

	// Primeras 2 llamadas consumen los tokens pre-llenados
	_, _ = sg.DialContext(ctx, "tcp", "127.0.0.1:80")
	_, _ = sg.DialContext(ctx, "tcp", "127.0.0.1:80")

	// La 3ra llamada inmediata en SafeMode debe rechazar con ErrRateLimitExceeded
	_, err = sg.DialContext(ctx, "tcp", "127.0.0.1:80")
	if !errors.Is(err, ErrRateLimitExceeded) {
		t.Errorf("expected ErrRateLimitExceeded in SafeMode when tokens exhausted, got: %v", err)
	}
}

func TestScopeGuard_LoadFromArgosJson(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "argos-scope-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}

	argosJsonContent := `{
		"$schema": "https://opencode.ai/config.json",
		"scope": {
			"allowed_domains": ["api.audit.target", "*.audit.target"],
			"allowed_cidrs": ["10.20.0.0/16"],
			"excluded_hosts": ["billing.audit.target"],
			"max_rps": 15,
			"custom_header": "X-Auditor-Engagement: ARGOS-TEST",
			"safe_mode": true
		}
	}`
	if err := os.WriteFile("argos.json", []byte(argosJsonContent), 0644); err != nil {
		t.Fatal(err)
	}

	sg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv failed: %v", err)
	}
	defer sg.Close()

	if !sg.IsDomainAllowed("app.audit.target") {
		t.Errorf("expected *.audit.target to match app.audit.target")
	}
	if !sg.IsDomainAllowed("api.audit.target") {
		t.Errorf("expected api.audit.target to be allowed")
	}
	if sg.IsDomainAllowed("billing.audit.target") {
		t.Errorf("expected billing.audit.target to be excluded")
	}
	if !sg.IsIPAllowed(net.ParseIP("10.20.1.5")) {
		t.Errorf("expected 10.20.1.5 in 10.20.0.0/16 to be allowed")
	}
	if sg.CustomHeader() != "X-Auditor-Engagement: ARGOS-TEST" {
		t.Errorf("expected custom header to be loaded, got %q", sg.CustomHeader())
	}
}

// fakeResolver resolves a fixed set of hosts, so the pinning logic can be
// exercised against controlled answers (DNS rebinding) without touching DNS.
type fakeResolver struct {
	hosts map[string][]net.IP
}

func (r fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if ips, ok := r.hosts[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

func TestScopeGuard_ClientRejectsOutOfScopeTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sg, err := New(ScopeConfig{
		AllowedCIDRs: []string{"203.0.113.0/24"},
		SessionID:    "test-sess-client",
		MaxRPS:       50,
	})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()

	client := sg.Client()

	// The loopback server is not part of the authorized scope: the client must
	// refuse to dial it.
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("expected the scope-bound client to reject an out-of-scope target")
	}

	// A target that is in scope still goes through.
	if !sg.Allowed("203.0.113.10") {
		t.Error("expected 203.0.113.10 to be allowed")
	}
	if sg.Allowed("127.0.0.1") {
		t.Error("expected 127.0.0.1 to be out of scope")
	}
}

func TestScopeGuard_RequiresWorkerProxyForHTTPAndDirectSockets(t *testing.T) {
	t.Setenv("ARGOS_WORKER_PROXY_URL", "")
	guard, err := New(ScopeConfig{RequireWorkerProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	if _, err := guard.DialContext(context.Background(), "tcp", "127.0.0.1:80"); !errors.Is(err, ErrWorkerProxyRequired) {
		t.Fatalf("direct socket error = %v, want ErrWorkerProxyRequired", err)
	}
	if _, err := guard.ValidateTarget(context.Background(), "http://scope-required.example.test/"); !errors.Is(err, ErrWorkerProxyRequired) {
		t.Fatalf("direct target validation error = %v, want ErrWorkerProxyRequired", err)
	}
	if guard.Allowed("scope-required.example.test") {
		t.Fatal("Allowed performed local DNS validation while worker proxy was required")
	}
	if _, err := guard.Client().Get("http://scope-required.example.test/"); !errors.Is(err, ErrWorkerProxyRequired) {
		t.Fatalf("HTTP error = %v, want ErrWorkerProxyRequired", err)
	}
}

func TestScopeGuard_DoesNotTrustAmbientLoopbackProxyForHostHTTP(t *testing.T) {
	var hits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	t.Setenv("ARGOS_WORKER_PROXY_URL", proxy.URL)

	guard, err := New(ScopeConfig{RequireWorkerProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	if _, err := guard.Client().Get("http://target.example.test/audit"); !errors.Is(err, ErrWorkerProxyRequired) {
		t.Fatalf("HTTP error = %v, want ErrWorkerProxyRequired without a runtime-owned worker proxy", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("ambient proxy received %d requests, want none", got)
	}
}

func TestScopeGuard_RejectsNonLoopbackWorkerProxy(t *testing.T) {
	t.Setenv("ARGOS_WORKER_PROXY_URL", "http://proxy.example.test:3128")
	guard, err := New(ScopeConfig{RequireWorkerProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	if _, err := guard.Client().Get("http://target.example.test/"); !errors.Is(err, ErrWorkerProxyRequired) {
		t.Fatalf("HTTP error = %v, want ErrWorkerProxyRequired", err)
	}
}

func TestScopeGuard_RebindingBlocked(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sg, err := New(ScopeConfig{
		AllowedDomains: []string{"rebind.example.com"},
		ExcludedHosts:  []string{"127.0.0.1"},
		SessionID:      "test-sess-rebind",
		MaxRPS:         50,
	})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()

	// The authorized domain answers with a loopback address: the guard must
	// refuse it instead of pinning the socket to it.
	sg.SetResolver(fakeResolver{hosts: map[string][]net.IP{
		"rebind.example.com": {net.ParseIP("127.0.0.1")},
	}})

	if _, err := sg.ValidateTarget(context.Background(), "rebind.example.com"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope for a rebinding host, got %v", err)
	}
	if sg.Allowed("rebind.example.com") {
		t.Error("expected Allowed to reject a host resolving to an excluded IP")
	}

	// The client must not emit the request either.
	client := sg.Client()
	if _, err := client.Get("http://rebind.example.com:1/"); err == nil {
		t.Fatal("expected the scope-bound client to block the rebinding host")
	}
	if hits != 0 {
		t.Errorf("expected no request to reach the server, got %d", hits)
	}
}

func TestScopeGuard_ExcludedPathsDomainsAndCIDRs(t *testing.T) {
	sg, err := New(ScopeConfig{
		AllowedDomains: []string{"app.example.com", "blocked.example.com"},
		AllowedCIDRs:   []string{"192.0.2.0/24"},
		ExcludedHosts:  []string{"/admin/*", "*.blocked.example.com", "192.0.2.128/25"},
		MaxRPS:         50,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sg.Close()
	sg.SetResolver(fakeResolver{hosts: map[string][]net.IP{
		"app.example.com": {net.ParseIP("203.0.113.10")},
	}})

	if _, err := sg.ValidateTarget(context.Background(), "https://app.example.com/admin/users"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected excluded route to be blocked, got %v", err)
	}
	if _, err := sg.ValidateTarget(context.Background(), "https://app.example.com/public"); err != nil {
		t.Fatalf("expected non-excluded route to be allowed, got %v", err)
	}
	if sg.IsDomainAllowed("api.blocked.example.com") {
		t.Fatal("expected wildcard-excluded domain to be blocked")
	}
	if sg.IsIPAllowed(net.ParseIP("192.0.2.200")) {
		t.Fatal("expected CIDR-excluded IP range to be blocked")
	}
}

func TestScopeGuard_MalformedPathFailsClosedWhenRouteExclusionsConfigured(t *testing.T) {
	sg, err := New(ScopeConfig{
		AllowedCIDRs:  []string{"127.0.0.0/8"},
		ExcludedHosts: []string{"/admin/*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sg.Close()

	if _, err := sg.ValidateTarget(context.Background(), "http://127.0.0.1/%zz"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("malformed target route error = %v, want ErrOutOfScope", err)
	}
}

func TestScopeGuard_HTTPRedirectCannotReachExcludedPath(t *testing.T) {
	var startHits atomic.Int32
	var excludedHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			startHits.Add(1)
			http.Redirect(w, r, "/admin/secret", http.StatusFound)
		case "/admin/secret":
			excludedHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	guard, err := New(ScopeConfig{
		AllowedCIDRs:  []string{"127.0.0.0/8"},
		ExcludedHosts: []string{"/admin/*"},
		MaxRPS:        50,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	_, err = guard.Client().Get(server.URL + "/admin/secret")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("direct request to excluded path error = %v, want ErrOutOfScope", err)
	}
	_, err = guard.Client().Get(server.URL + "/start")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("redirect to excluded path error = %v, want ErrOutOfScope", err)
	}
	if got := startHits.Load(); got != 1 {
		t.Fatalf("allowed route hits = %d, want 1", got)
	}
	if got := excludedHits.Load(); got != 0 {
		t.Fatalf("excluded route was reached %d times", got)
	}
}

func TestScopeGuard_ClientRequestIsChainedInAuditLog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ARGOS_SCOPE_OK"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	sg, err := New(ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "test-sess-audit",
		AuditLogDir:  tmpDir,
		MaxRPS:       50,
	})
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	defer sg.Close()

	resp, err := sg.Client().Get(server.URL + "/audited")
	if err != nil {
		t.Fatalf("scoped client request failed: %v", err)
	}
	resp.Body.Close()

	auditPath := filepath.Join(tmpDir, "audit-test-sess-audit.jsonl")
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("audit file not created: %v", err)
	}
	defer file.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		t.Fatal("expected audit entries for the scoped request")
	}

	var lastHash string
	for i, e := range entries {
		if e.PrevHash != lastHash {
			t.Errorf("entry %d prev_hash mismatch: expected %q, got %q", i, lastHash, e.PrevHash)
		}
		if e.Hash == "" {
			t.Errorf("entry %d missing hash", i)
		}
		lastHash = e.Hash
	}

	// The dial itself must be recorded: that is the entry that proves the
	// request was pinned and audited.
	found := false
	for _, e := range entries {
		if e.Action == "DIAL_CONNECT" && e.Status == "ESTABLISHED" {
			found = true
			if e.IP != "127.0.0.1" {
				t.Errorf("expected the pinned IP to be recorded, got %q", e.IP)
			}
		}
	}
	if !found {
		t.Error("expected an ESTABLISHED DIAL_CONNECT entry in the audit log")
	}
}

func TestScopeGuardCreatesOperationScopedAuditLogByDefault(t *testing.T) {
	auditRoot := t.TempDir()
	t.Setenv("ARGOS_AUDIT_LOG_DIR", auditRoot)

	guard, err := New(ScopeConfig{
		AllowedDomains: []string{"app.example.test"},
		SessionID:      "ses_operation_audit",
		OperationID:    "call_operation_audit",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	guard.LogAudit("app.example.test", "203.0.113.10", "443", "TEST", "RECORDED", nil)

	var auditFiles []string
	err = filepath.WalkDir(auditRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			auditFiles = append(auditFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(auditFiles) != 1 {
		t.Fatalf("audit files = %d, want one operation-specific log", len(auditFiles))
	}
	data, err := os.ReadFile(auditFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.SessionID != "ses_operation_audit" || entry.OperationID != "call_operation_audit" {
		t.Fatalf("audit identity = session %q operation %q", entry.SessionID, entry.OperationID)
	}
}

func TestScopeGuardFailsWhenAuditLogCannotBePrepared(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ScopeConfig{
		AllowedDomains: []string{"app.example.test"},
		SessionID:      "ses_audit_preflight",
		OperationID:    "op_audit_preflight",
		AuditLogDir:    file,
	}); err == nil {
		t.Fatal("scope guard started without a writable audit log")
	}
}

func TestScopeGuardFailsClosedWhenAuditWriteFails(t *testing.T) {
	auditDir := t.TempDir()
	guard, err := New(ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "ses_audit_failure",
		AuditLogDir:  auditDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := os.RemoveAll(auditDir); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.ValidateTarget(context.Background(), "127.0.0.1"); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("target validation = %v, want an audit failure", err)
	}
}

func TestAuditEntryHashIncludesPortAndMetadata(t *testing.T) {
	base := AuditEntry{
		Timestamp: time.Date(2026, time.January, 2, 3, 4, 5, 6, time.UTC),
		SessionID: "ses_hash_fields",
		Target:    "app.example.test",
		IP:        "203.0.113.10",
		Port:      "443",
		Action:    "DIAL_CONNECT",
		Status:    "ESTABLISHED",
		Meta:      map[string]any{"method": "GET"},
	}
	baseHash, err := auditEntryHash(base)
	if err != nil {
		t.Fatal(err)
	}
	portChanged := base
	portChanged.Port = "8443"
	portHash, err := auditEntryHash(portChanged)
	if err != nil {
		t.Fatal(err)
	}
	metaChanged := base
	metaChanged.Meta = map[string]any{"method": "POST"}
	metaHash, err := auditEntryHash(metaChanged)
	if err != nil {
		t.Fatal(err)
	}
	if baseHash == portHash || baseHash == metaHash {
		t.Fatal("audit hash did not cover port and metadata")
	}
}

func TestVerifyAuditLogDetectsModifiedEvidence(t *testing.T) {
	auditDir := t.TempDir()
	guard, err := New(ScopeConfig{
		AllowedDomains: []string{"app.example.test"},
		SessionID:      "ses_audit_verify",
		AuditLogDir:    auditDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.LogAudit("app.example.test", "203.0.113.10", "443", "REQUEST", "RECORDED", map[string]any{"method": "GET"}); err != nil {
		t.Fatal(err)
	}
	guard.Close()
	path := filepath.Join(auditDir, "audit-ses_audit_verify.jsonl")
	if err := VerifyAuditLog(path); err != nil {
		t.Fatalf("valid audit log failed verification: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatal(err)
	}
	entry.Port = "8443"
	modified, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(modified, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuditLog(path); err == nil {
		t.Fatal("audit log verification accepted modified port evidence")
	}
}

func TestScopeGuardContinuesTheExistingAuditChain(t *testing.T) {
	auditDir := t.TempDir()
	config := ScopeConfig{AllowedDomains: []string{"app.example.test"}, SessionID: "ses_audit_resume", AuditLogDir: auditDir}
	first, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.LogAudit("app.example.test", "203.0.113.10", "443", "REQUEST", "FIRST", nil); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.LogAudit("app.example.test", "203.0.113.10", "443", "REQUEST", "SECOND", nil); err != nil {
		t.Fatal(err)
	}
	second.Close()
	if err := VerifyAuditLog(filepath.Join(auditDir, "audit-ses_audit_resume.jsonl")); err != nil {
		t.Fatalf("continued audit chain failed verification: %v", err)
	}
}

func TestVerifyAuditLogAcceptsLegacyChainEntries(t *testing.T) {
	entry := AuditEntry{
		Timestamp: time.Date(2026, time.January, 2, 3, 4, 5, 6, time.UTC),
		SessionID: "ses_legacy_audit",
		Target:    "app.example.test",
		IP:        "203.0.113.10",
		Port:      "443",
		Action:    "REQUEST",
		Status:    "RECORDED",
	}
	entry.Hash = legacyAuditEntryHash(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.jsonl")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuditLog(path); err != nil {
		t.Fatalf("legacy audit entry failed verification: %v", err)
	}
	verification, err := VerifyAuditLogDetailed(path)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Entries != 1 || verification.LegacyEntries != 1 || verification.DisconnectedLegacyRuns != 0 {
		t.Fatalf("legacy verification details = %+v", verification)
	}
}
