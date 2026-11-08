package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// wordlistTestServer serves the pinned wordlist files and counts the
// downloads.
func wordlistTestServer(t *testing.T, body []byte, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// useWordlistServer points the downloader at a local server for the
// duration of the test.
func useWordlistServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := rawGitHubBase
	rawGitHubBase = srv.URL
	t.Cleanup(func() { rawGitHubBase = old })
}

func sha256Of(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// withWordlistSpec swaps a registry entry for the duration of the test so
// a locally served body can match the pinned checksum.
func withWordlistSpec(t *testing.T, name string, mutate func(*WordlistSpec)) {
	t.Helper()
	idx := -1
	for i := range wordlistRegistry {
		if wordlistRegistry[i].Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("the registry has no %q", name)
	}
	original := wordlistRegistry[idx]
	mutate(&wordlistRegistry[idx])
	t.Cleanup(func() { wordlistRegistry[idx] = original })
}

func TestResolveWordlist_Aliases(t *testing.T) {
	cases := map[string]string{
		"dirs":   "raft-large-words",
		"big":    "raft-large-words",
		"small":  "raft-small-words",
		"api":    "api-endpoints",
		"dns":    "dns",
		"hosts":  "dns",
		"params": "param-names",
		"common": "common",
		"bypass": "bypass",
	}
	for alias, want := range cases {
		spec, ok := ResolveWordlist(alias)
		if !ok {
			t.Fatalf("alias %q did not resolve", alias)
		}
		if spec.Name != want {
			t.Errorf("alias %q = %q, want %q", alias, spec.Name, want)
		}
	}
	if _, ok := ResolveWordlist("does-not-exist"); ok {
		t.Error("an unknown wordlist must not resolve")
	}
	// the concrete names resolve as well
	if spec, ok := ResolveWordlist("raft-large-words"); !ok || spec.Name != "raft-large-words" {
		t.Errorf("concrete name did not resolve: %+v", spec)
	}
}

func TestAvailableWordlists_Metadata(t *testing.T) {
	specs := AvailableWordlists()
	if len(specs) == 0 {
		t.Fatal("the registry is empty")
	}
	names := map[string]bool{}
	for _, spec := range specs {
		if spec.Name == "" || spec.Repo == "" || spec.Path == "" || spec.Version == "" {
			t.Errorf("incomplete spec: %+v", spec)
		}
		if spec.Lines <= 0 {
			t.Errorf("%s has no line count: %+v", spec.Name, spec)
		}
		if spec.Kind == "" {
			t.Errorf("%s has no kind: %+v", spec.Name, spec)
		}
		if spec.SHA256 != "" && len(spec.SHA256) != 64 {
			t.Errorf("%s has a malformed sha256: %q", spec.Name, spec.SHA256)
		}
		names[spec.Name] = true
	}
	for _, want := range []string{"raft-large-words", "raft-small-words", "common", "api-endpoints", "param-names", "dns", "bypass"} {
		if !names[want] {
			t.Errorf("the registry is missing %q", want)
		}
	}
}

// The catalogue tool must be registered with its metadata.
func TestRegisterWordlists(t *testing.T) {
	s := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "1.0.0"})
	RegisterWordlists(s, NewEnv(t.TempDir()))
	found := false
	for _, def := range s.ToolDefinitions() {
		if def.Name == "web.wordlists" {
			found = true
			if def.InputSchema.Properties["kind"].Type != "string" {
				t.Error("web.wordlists must expose the kind filter")
			}
		}
	}
	if !found {
		t.Fatal("web.wordlists was not registered")
	}
}

// The catalogue reports the wordlists with their metadata and cache state.
func TestWebWordlists_Result(t *testing.T) {
	s := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "1.0.0"})
	env := NewEnv(t.TempDir())
	RegisterWordlists(s, env)
	handler := s.GetToolHandler("web.wordlists")
	if handler == nil {
		t.Fatal("web.wordlists has no handler")
	}
	res, errObj := handler(mcp.ToolContext{}, json.RawMessage(`{"kind":"dirs"}`))
	if errObj != nil {
		t.Fatalf("web.wordlists failed: %v", errObj)
	}
	out, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result: %v", res)
	}
	items, ok := out["wordlists"].([]map[string]interface{})
	if !ok {
		t.Fatalf("no wordlists in the result: %v", out)
	}
	if len(items) == 0 {
		t.Fatal("the dirs filter returned no wordlist")
	}
	for _, item := range items {
		if item["name"] == "" || item["kind"] == "" {
			t.Errorf("incomplete entry: %v", item)
		}
		if item["kind"] != "dirs" {
			t.Errorf("the filter leaked %v", item)
		}
		if item["cached"] != false {
			t.Errorf("a wordlist that was never fetched must not be cached: %v", item)
		}
	}
	if out["profiles"] == nil {
		t.Error("the catalogue must expose the profiles")
	}
}

func TestEnsureWordlist_Idempotent(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	body := []byte("admin\nbackup\nconfig\n")
	spec, ok := ResolveWordlist("raft-small-words")
	if !ok {
		t.Fatal("raft-small-words is not in the registry")
	}
	// the pin of the registry does not match the served body: the test
	// overrides the spec through a dedicated entry.
	withWordlistSpec(t, "raft-small-words", func(s *WordlistSpec) { s.SHA256 = sha256Of(body) })

	var hits int32
	srv := wordlistTestServer(t, body, &hits)
	useWordlistServer(t, srv)

	toolsDir := t.TempDir()
	path, resolved, err := EnsureWordlistIn(context.Background(), toolsDir, "small")
	if err != nil {
		t.Fatalf("EnsureWordlistIn failed: %v", err)
	}
	if resolved.Name != "raft-small-words" {
		t.Errorf("resolved %q, want raft-small-words", resolved.Name)
	}
	if resolved.Source != wordlistSourceDownloaded {
		t.Errorf("source = %q, want %q", resolved.Source, wordlistSourceDownloaded)
	}
	want := filepath.Join(toolsDir, wordlistCacheDir, "raft-small-words-"+spec.Version+".txt")
	if path != want {
		t.Errorf("cache path = %q, want %q", path, want)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(body) {
		t.Fatalf("the cached wordlist does not hold the served content: %v", err)
	}

	// the second call must not download again
	path2, resolved2, err := EnsureWordlistIn(context.Background(), toolsDir, "small")
	if err != nil {
		t.Fatalf("the second EnsureWordlistIn failed: %v", err)
	}
	if path2 != path {
		t.Errorf("the second call returned %q, want %q", path2, path)
	}
	if resolved2.Source != wordlistSourceCached {
		t.Errorf("source = %q, want %q", resolved2.Source, wordlistSourceCached)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("the wordlist was downloaded %d times, want 1", n)
	}
}

// A wrong pin must not reach a scanner: the run degrades to the bundled
// list and declares it.
func TestEnsureWordlist_ChecksumMismatchFallsBackToBundled(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	body := []byte("admin\nbackup\n")
	var hits int32
	srv := wordlistTestServer(t, body, &hits)
	useWordlistServer(t, srv)

	toolsDir := t.TempDir()
	path, spec, err := EnsureWordlistIn(context.Background(), toolsDir, "dirs")
	if err != nil {
		t.Fatalf("EnsureWordlistIn failed: %v", err)
	}
	if spec.Source != wordlistSourceBundled {
		t.Errorf("source = %q, want %q", spec.Source, wordlistSourceBundled)
	}
	if !strings.Contains(path, "bundled") {
		t.Errorf("the fallback must be the bundled list, got %q", path)
	}
	// the tampered download must not be cached
	cache := filepath.Join(toolsDir, wordlistCacheDir, "raft-large-words-"+seclistsVersion+".txt")
	if _, err := os.Stat(cache); err == nil {
		t.Error("a rejected download must not be cached")
	}
}

// Without network the run falls back to the bundled common.txt and says so.
func TestEnsureWordlist_OfflineFallsBackToBundled(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	var hits int32
	srv := wordlistTestServer(t, []byte("x\n"), &hits)
	base := srv.URL
	srv.Close()
	old := rawGitHubBase
	rawGitHubBase = base
	defer func() { rawGitHubBase = old }()

	toolsDir := t.TempDir()
	path, spec, err := EnsureWordlistIn(context.Background(), toolsDir, "dirs")
	if err != nil {
		t.Fatalf("EnsureWordlistIn failed offline: %v", err)
	}
	if spec.Source != wordlistSourceBundled {
		t.Errorf("source = %q, want %q", spec.Source, wordlistSourceBundled)
	}
	if !strings.Contains(path, "bundled") {
		t.Errorf("the fallback must be the bundled list, got %q", path)
	}
	entries, err := countWordlistEntries(path)
	if err != nil {
		t.Fatalf("cannot count the fallback entries: %v", err)
	}
	if entries != len(fallbackWordlist) {
		t.Errorf("the fallback holds %d entries, want %d", entries, len(fallbackWordlist))
	}
}

// The bundled common.txt shipped with the skill is the offline fallback
// when the config dir exposes it.
func TestEnsureWordlist_OfflineUsesSkillCommonTxt(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")

	cfgDir := t.TempDir()
	wlDir := filepath.Join(cfgDir, "skills", "auditoria-web", "scripts", "wordlists")
	if err := os.MkdirAll(wlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	skillList := filepath.Join(wlDir, "common.txt")
	if err := os.WriteFile(skillList, []byte("admin\nbackup\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", cfgDir)

	var hits int32
	srv := wordlistTestServer(t, []byte("x\n"), &hits)
	base := srv.URL
	srv.Close()
	old := rawGitHubBase
	rawGitHubBase = base
	defer func() { rawGitHubBase = old }()

	path, spec, err := EnsureWordlistIn(context.Background(), t.TempDir(), "dirs")
	if err != nil {
		t.Fatalf("EnsureWordlistIn failed offline: %v", err)
	}
	if path != skillList {
		t.Errorf("fallback = %q, want the skill common.txt %q", path, skillList)
	}
	if spec.Source != wordlistSourceBundled {
		t.Errorf("source = %q, want %q", spec.Source, wordlistSourceBundled)
	}
}

func TestEnsureWordlist_UnknownProfile(t *testing.T) {
	_, _, err := EnsureWordlistIn(context.Background(), t.TempDir(), "nope")
	if err == nil {
		t.Fatal("an unknown wordlist must fail")
	}
	if !strings.Contains(err.Error(), "unknown wordlist") {
		t.Errorf("unexpected error: %v", err)
	}
}

// A cached wordlist older than the TTL is re-verified, not blindly
// re-downloaded.
func TestEnsureWordlist_StaleIsReverifiedWithoutDownload(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("ARGOS_WORDLIST_TTL_DAYS", "0")

	body := []byte("admin\nbackup\n")
	withWordlistSpec(t, "common", func(s *WordlistSpec) { s.SHA256 = sha256Of(body) })

	var hits int32
	srv := wordlistTestServer(t, body, &hits)
	useWordlistServer(t, srv)

	toolsDir := t.TempDir()
	spec, _ := ResolveWordlist("common")
	cache := filepath.Join(toolsDir, wordlistCacheDir, "common-"+spec.Version+".txt")
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, body, 0o644); err != nil {
		t.Fatal(err)
	}
	_, resolved, err := EnsureWordlistIn(context.Background(), toolsDir, "common")
	if err != nil {
		t.Fatalf("EnsureWordlistIn failed: %v", err)
	}
	if resolved.Source != wordlistSourceCached {
		t.Errorf("source = %q, want %q", resolved.Source, wordlistSourceCached)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("a cached wordlist that matches the pin was downloaded %d times, want 0", n)
	}
}

// A cached wordlist that no longer matches the pin is replaced.
func TestEnsureWordlist_StaleCorruptedIsRedownloaded(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("ARGOS_WORDLIST_TTL_DAYS", "0")

	body := []byte("admin\nbackup\n")
	withWordlistSpec(t, "common", func(s *WordlistSpec) { s.SHA256 = sha256Of(body) })

	var hits int32
	srv := wordlistTestServer(t, body, &hits)
	useWordlistServer(t, srv)

	toolsDir := t.TempDir()
	spec, _ := ResolveWordlist("common")
	cache := filepath.Join(toolsDir, wordlistCacheDir, "common-"+spec.Version+".txt")
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, resolved, err := EnsureWordlistIn(context.Background(), toolsDir, "common")
	if err != nil {
		t.Fatalf("EnsureWordlistIn failed: %v", err)
	}
	if resolved.Source != wordlistSourceDownloaded {
		t.Errorf("source = %q, want %q", resolved.Source, wordlistSourceDownloaded)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("the corrupted wordlist was downloaded %d times, want 1", n)
	}
	data, err := os.ReadFile(cache)
	if err != nil || string(data) != string(body) {
		t.Errorf("the cache was not refreshed: %v", err)
	}
}

// EnsureWordlist resolves the tools directory from the environment.
func TestEnsureWordlist_UsesToolsDirEnv(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	body := []byte("admin\nbackup\n")
	withWordlistSpec(t, "raft-small-words", func(s *WordlistSpec) { s.SHA256 = sha256Of(body) })
	var hits int32
	srv := wordlistTestServer(t, body, &hits)
	useWordlistServer(t, srv)

	toolsDir := t.TempDir()
	t.Setenv("ARGOS_TOOLS_DIR", toolsDir)

	path, spec, err := EnsureWordlist(context.Background(), "small")
	if err != nil {
		t.Fatalf("EnsureWordlist failed: %v", err)
	}
	if !strings.HasPrefix(path, toolsDir) {
		t.Errorf("the wordlist was cached outside the tools dir: %q", path)
	}
	if spec.Name != "raft-small-words" {
		t.Errorf("resolved %q, want raft-small-words", spec.Name)
	}
	if spec.Source != wordlistSourceDownloaded {
		t.Errorf("source = %q, want %q", spec.Source, wordlistSourceDownloaded)
	}
}

func TestDefaultWordlistProfile(t *testing.T) {
	cases := map[string]string{
		"dir":   "dirs",
		"vhost": "hosts",
		"param": "params",
		"":      "dirs",
	}
	for mode, want := range cases {
		if got := defaultWordlistProfile(mode); got != want {
			t.Errorf("mode %q = %q, want %q", mode, got, want)
		}
	}
}

// The ffuf command line must point at the resolved wordlist.
func TestFuzzArgs_UsesResolvedWordlist(t *testing.T) {
	wl := filepath.Join("/tools", "wordlists", "raft-large-words-2026.1.txt")
	args := fuzzArgs("https://example.com", "dir", wl, 50, nil)
	if v, ok := argValue(args, "-w"); !ok || v != wl+":FUZZ" {
		t.Errorf("-w = %q (found=%v), want %q", v, ok, wl+":FUZZ")
	}
	if v, ok := argValue(args, "-u"); !ok || v != "https://example.com/FUZZ" {
		t.Errorf("-u = %q (found=%v), want the fuzzed target", v, ok)
	}
}

func TestFuzzArgs_VhostAndFilters(t *testing.T) {
	wl := "/tools/wordlists/dns-2026.1.txt"
	args := fuzzArgs("https://example.com", "vhost", wl, 20, []int{404, 500})
	if v, ok := argValue(args, "-w"); !ok || v != wl+":FUZZ" {
		t.Errorf("-w = %q (found=%v), want %q", v, ok, wl+":FUZZ")
	}
	if v, ok := argValue(args, "-H"); !ok || v != "Host: FUZZ.example.com" {
		t.Errorf("-H = %q (found=%v), want the vhost header", v, ok)
	}
	if v, ok := argValue(args, "-fc"); !ok || v != "404,500" {
		t.Errorf("-fc = %q (found=%v), want 404,500", v, ok)
	}
}

func TestParamsArgs_UsesResolvedWordlist(t *testing.T) {
	wl := "/tools/wordlists/param-names-2026.1.txt"
	args := paramsArgs("https://example.com/search", "GET", wl)
	if v, ok := argValue(args, "-w"); !ok || v != wl+":FUZZ" {
		t.Errorf("-w = %q (found=%v), want %q", v, ok, wl+":FUZZ")
	}
	if v, ok := argValue(args, "-u"); !ok || v != "https://example.com/search?FUZZ=argos-probe" {
		t.Errorf("-u = %q (found=%v), want the probed target", v, ok)
	}
	post := paramsArgs("https://example.com/search", "POST", wl)
	if v, ok := argValue(post, "-d"); !ok || v != "FUZZ=argos-probe" {
		t.Errorf("-d = %q (found=%v), want the fuzzed body", v, ok)
	}
}

// The wordlist the "dirs" profile resolves to is the big raft list.
func TestFuzzDirsProfileResolvesRaftLarge(t *testing.T) {
	spec, ok := ResolveWordlist("dirs")
	if !ok {
		t.Fatal("the dirs profile did not resolve")
	}
	if spec.Name != "raft-large-words" {
		t.Errorf("dirs = %q, want raft-large-words", spec.Name)
	}
	if spec.Lines < 10000 {
		t.Errorf("the dirs profile holds %d entries, expected a deep list", spec.Lines)
	}
}

func TestWordlistEntry_ReportsCacheState(t *testing.T) {
	toolsDir := t.TempDir()
	spec, _ := ResolveWordlist("common")
	entry := wordlistEntry(spec, toolsDir)
	if entry["cached"] != false {
		t.Error("a wordlist that was never fetched must not be reported as cached")
	}
	cache := wordlistCachePath(toolsDir, spec)
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry = wordlistEntry(spec, toolsDir)
	if entry["cached"] != true {
		t.Error("a cached wordlist must be reported as cached")
	}
	if entry["cache_path"] != cache {
		t.Errorf("cache path = %v, want %q", entry["cache_path"], cache)
	}
}

func TestCountWordlistEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte("a\n\n b \n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := countWordlistEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("entries = %d, want 2", got)
	}
}

func TestWordlistCachePath_IsVersioned(t *testing.T) {
	spec, _ := ResolveWordlist("common")
	path := wordlistCachePath("/tools", spec)
	want := fmt.Sprintf("/tools/wordlists/common-%s.txt", spec.Version)
	if filepath.ToSlash(path) != want {
		t.Errorf("cache path = %q, want %q", path, want)
	}
}

// TestEnsureWordlist_LiveDownload exercises the real upstream: it proves
// the pinned URLs and the pinned checksums still hold. It is skipped
// unless ARGOS_WORDLIST_E2E=1 so the suite stays offline-safe.
func TestEnsureWordlist_LiveDownload(t *testing.T) {
	if os.Getenv("ARGOS_WORDLIST_E2E") != "1" {
		t.Skip("set ARGOS_WORDLIST_E2E=1 to run the live wordlist download")
	}
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	toolsDir := t.TempDir()
	for _, profile := range []string{"dirs", "small", "api", "params", "dns", "bypass"} {
		path, spec, err := EnsureWordlistIn(context.Background(), toolsDir, profile)
		if err != nil {
			t.Fatalf("%s: EnsureWordlistIn failed: %v", profile, err)
		}
		if spec.Source != wordlistSourceDownloaded {
			t.Errorf("%s: source = %q, want %q", profile, spec.Source, wordlistSourceDownloaded)
		}
		entries, err := countWordlistEntries(path)
		if err != nil {
			t.Fatalf("%s: cannot count the entries: %v", profile, err)
		}
		if entries != spec.Lines {
			t.Errorf("%s: the file holds %d entries, the pin declares %d", profile, entries, spec.Lines)
		}
	}
}
