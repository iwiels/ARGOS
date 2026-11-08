package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// allowList is a ScopeValidator stub: it authorizes a fixed set of hosts.
type allowList struct {
	allowed map[string]bool
}

func (a allowList) ValidateTarget(_ context.Context, rawTarget string) (string, error) {
	host := HostOfURL(rawTarget)
	if host == "" {
		host = rawTarget
	}
	if a.allowed[host] {
		return host, nil
	}
	return "", errors.New("SECURITY ENFORCEMENT: Target is out of authorized scope")
}

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store := NewStore(dir)
	t.Setenv(MaxExchangesEnv, "")
	return store
}

func sampleExchange(t *testing.T, id, method, url string, status int, body string) Exchange {
	t.Helper()
	return Exchange{
		ID:          id,
		SessionID:   "ses_traffic_test",
		Timestamp:   time.Now().UTC(),
		Method:      method,
		URL:         url,
		Headers:     map[string][]string{"Accept": {"*/*"}},
		RequestBody: []byte("id=1"),
		Status:      status,
		ResponseHeaders: map[string][]string{
			"Content-Type": {"text/html"},
		},
		ResponseBody: []byte(body),
		DurationMs:   42,
		SourceTool:   "web.probe",
		Target:       url,
		ScopeAllowed: true,
	}
}

func TestRecordListGet(t *testing.T) {
	store := newStore(t)
	first := sampleExchange(t, "ex_one", "GET", "https://example.com/a", 200, "hello")
	second := sampleExchange(t, "ex_two", "POST", "https://example.com/b", 404, "missing")
	second.Timestamp = first.Timestamp.Add(time.Second)

	if err := store.Record(first); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := store.Record(second); err != nil {
		t.Fatalf("Record: %v", err)
	}

	all, total := store.List("ses_traffic_test", Filter{})
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if len(all) != 2 {
		t.Fatalf("list length = %d, want 2", len(all))
	}
	if all[0].ID != "ex_one" || all[1].ID != "ex_two" {
		t.Errorf("list is not chronological: %s, %s", all[0].ID, all[1].ID)
	}

	filtered, total := store.List("ses_traffic_test", Filter{Method: "POST"})
	if total != 2 {
		t.Errorf("total = %d, want 2 (the total counts the session, not the filter)", total)
	}
	if len(filtered) != 1 || filtered[0].ID != "ex_two" {
		t.Fatalf("filtered = %+v, want only ex_two", filtered)
	}

	byStatus, _ := store.List("ses_traffic_test", Filter{Status: "4xx"})
	if len(byStatus) != 1 || byStatus[0].ID != "ex_two" {
		t.Fatalf("status filter returned %+v, want only ex_two", byStatus)
	}

	byHost, _ := store.List("ses_traffic_test", Filter{Host: "example.com"})
	if len(byHost) != 2 {
		t.Fatalf("host filter returned %d exchanges, want 2", len(byHost))
	}

	byTool, _ := store.List("ses_traffic_test", Filter{SourceTool: "web.tls"})
	if len(byTool) != 0 {
		t.Fatalf("tool filter returned %d exchanges, want 0", len(byTool))
	}

	got, ok := store.Get("ses_traffic_test", "ex_one")
	if !ok {
		t.Fatal("Get did not find the exchange")
	}
	if got.Status != 200 || string(got.ResponseBody) != "hello" {
		t.Errorf("Get returned %+v", got)
	}
	if _, ok := store.Get("ses_traffic_test", "ex_missing"); ok {
		t.Error("Get found an exchange that does not exist")
	}
}

func TestPersistedExchangeRedactsCredentials(t *testing.T) {
	store := newStore(t)
	ex := sampleExchange(t, "ex_secret", "GET", "https://example.com/login?token=supersecret", 200, "ok")
	ex.Headers = map[string][]string{
		"Authorization": {"Bearer super-secret-token"},
		"Cookie":        {"session=abc123; theme=dark"},
		"Set-Cookie":    {"session=abc123; HttpOnly"},
		"X-Api-Key":     {"key-9999"},
		"Accept":        {"*/*"},
	}
	ex.RequestBody = []byte("user=admin&password=hunter2")

	if err := store.Record(ex); err != nil {
		t.Fatalf("Record: %v", err)
	}

	path := filepath.Join(store.BaseDir, "ses_traffic_test", "ex_secret.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted exchange: %v", err)
	}
	content := string(raw)

	for _, secret := range []string{"super-secret-token", "abc123", "key-9999", "hunter2", "supersecret"} {
		if strings.Contains(content, secret) {
			t.Errorf("the persisted exchange leaks %q:\n%s", secret, content)
		}
	}
	if !strings.Contains(content, "Bearer ***") {
		t.Errorf("the persisted exchange lost the auth scheme:\n%s", content)
	}
	if !strings.Contains(content, "session=***") {
		t.Errorf("the persisted exchange lost the cookie names:\n%s", content)
	}

	var stored persistedExchange
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("the persisted exchange is not valid JSON: %v", err)
	}
	if stored.RequestBody == nil || stored.RequestBody.SHA256 == "" {
		t.Error("the persisted exchange has no body hash")
	}
	if stored.ResponseBody == nil || stored.ResponseBody.SHA256 == "" {
		t.Error("the persisted response has no body hash")
	}
	if stored.RequestBody.SHA256 != BodyHash(RedactRequestBody(ex.RequestBody)) {
		t.Error("the body hash does not match the stored body")
	}
}

func TestEvictionKeepsTheCap(t *testing.T) {
	t.Setenv(MaxExchangesEnv, "3")
	store := NewStore(t.TempDir())

	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		ex := sampleExchange(t, "ex_"+string(rune('a'+i)), "GET", "https://example.com/", 200, "body")
		ex.Timestamp = base.Add(time.Duration(i) * time.Second)
		if err := store.Record(ex); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	_, total := store.List("ses_traffic_test", Filter{})
	if total != 3 {
		t.Fatalf("total = %d, want 3 (the cap)", total)
	}
	all, _ := store.List("ses_traffic_test", Filter{})
	if all[0].ID != "ex_c" {
		t.Errorf("the oldest exchanges were not evicted: first = %s", all[0].ID)
	}
	if _, ok := store.Get("ses_traffic_test", "ex_a"); ok {
		t.Error("the evicted exchange is still in the store")
	}
}

func TestDiffDetectsStatusHeaderAndBodyChanges(t *testing.T) {
	store := newStore(t)
	a := sampleExchange(t, "ex_a", "GET", "https://example.com/", 200, "line1\nline2\nline3")
	b := sampleExchange(t, "ex_b", "GET", "https://example.com/", 500, "line1\nline changed\nline3")
	b.ResponseHeaders = map[string][]string{
		"Content-Type": {"application/json"},
		"X-New":        {"1"},
	}

	if err := store.Record(a); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := store.Record(b); err != nil {
		t.Fatalf("Record: %v", err)
	}

	result, err := store.Diff("ses_traffic_test", "ex_a", "ex_b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !result.StatusChanged || result.StatusA != 200 || result.StatusB != 500 {
		t.Errorf("the status change was not detected: %+v", result)
	}
	if !result.BodyChanged {
		t.Error("the body change was not detected")
	}
	if !strings.Contains(result.BodyDiff, "-line2") || !strings.Contains(result.BodyDiff, "+line changed") {
		t.Errorf("the unified diff does not carry the change:\n%s", result.BodyDiff)
	}
	if result.BodyLinesAdded != 1 || result.BodyLinesRemoved != 1 {
		t.Errorf("diff counters = +%d -%d, want +1 -1", result.BodyLinesAdded, result.BodyLinesRemoved)
	}
	if len(result.HeadersAdded) != 1 || result.HeadersAdded[0].Name != "x-new" {
		t.Errorf("the added header was not detected: %+v", result.HeadersAdded)
	}
	if len(result.HeadersChanged) != 1 || result.HeadersChanged[0].Name != "content-type" {
		t.Errorf("the changed header was not detected: %+v", result.HeadersChanged)
	}
	if result.Identical {
		t.Error("two different exchanges were reported as identical")
	}

	if _, err := store.Diff("ses_traffic_test", "ex_a", "ex_missing"); err == nil {
		t.Error("Diff did not fail on a missing exchange")
	}
}

func TestDiffOfIdenticalExchanges(t *testing.T) {
	a := sampleExchange(t, "ex_a", "GET", "https://example.com/", 200, "same")
	b := sampleExchange(t, "ex_b", "GET", "https://example.com/", 200, "same")
	result := DiffExchanges(a, b)
	if !result.Identical {
		t.Errorf("two identical exchanges were reported as different: %+v", result)
	}
	if result.BodyDiff != "" {
		t.Errorf("an identical body produced a diff:\n%s", result.BodyDiff)
	}
}

func TestReplayAppliesOverridesAndRecordsTheResponse(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Query().Get("id") == "2" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("original"))
	}))
	defer srv.Close()

	store := NewStore(t.TempDir())
	original := sampleExchange(t, "ex_original", "GET", srv.URL+"?id=1", 200, "original")
	if err := store.Record(original); err != nil {
		t.Fatalf("Record: %v", err)
	}

	client := srv.Client()
	store = NewStoreWithScope(t.TempDir(), client, allowList{allowed: map[string]bool{"127.0.0.1": true}})
	// The original exchange has to live in the store the replay reads from.
	if err := store.Record(original); err != nil {
		t.Fatalf("Record: %v", err)
	}

	replayed, err := store.Replay(context.Background(), "ses_traffic_test", "ex_original", Overrides{
		URL:  srv.URL + "?id=2",
		Body: []byte("payload"),
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed.Status != 500 {
		t.Errorf("replayed status = %d, want 500", replayed.Status)
	}
	if string(replayed.ResponseBody) != "boom" {
		t.Errorf("replayed body = %q, want %q", replayed.ResponseBody, "boom")
	}
	if replayed.ID == original.ID {
		t.Error("the replayed exchange reused the id of the original")
	}
	if _, ok := store.Get("ses_traffic_test", replayed.ID); !ok {
		t.Error("the replayed exchange was not recorded")
	}

	result, err := store.Diff("ses_traffic_test", original.ID, replayed.ID)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !result.StatusChanged {
		t.Error("the diff did not detect the status change of the replay")
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("hits = %d, want 1", n)
	}
}

func TestReplayOutOfScopeEmitsNoRequest(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewStoreWithScope(t.TempDir(), srv.Client(), allowList{allowed: map[string]bool{}})
	original := sampleExchange(t, "ex_original", "GET", srv.URL, 200, "original")
	if err := store.Record(original); err != nil {
		t.Fatalf("Record: %v", err)
	}

	_, err := store.Replay(context.Background(), "ses_traffic_test", "ex_original", Overrides{
		URL: srv.URL + "?id=2",
	})
	if err == nil {
		t.Fatal("the replay of an out-of-scope target was allowed")
	}
	if !strings.Contains(err.Error(), "SCOPE ENFORCEMENT") {
		t.Errorf("error = %q, want a SCOPE ENFORCEMENT error", err.Error())
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("hits = %d, want 0: an out-of-scope replay must not emit a request", n)
	}
}

func TestUnifiedDiffFormat(t *testing.T) {
	a := []byte("one\ntwo\nthree\n")
	b := []byte("one\nTWO\nthree\n")
	diff := UnifiedDiff("a", "b", a, b)
	if !strings.HasPrefix(diff, "--- a/a\n+++ b/b\n") {
		t.Errorf("the diff does not start with the unified header:\n%s", diff)
	}
	if !strings.Contains(diff, "@@ -1,3 +1,3 @@") {
		t.Errorf("the diff does not carry a hunk header:\n%s", diff)
	}
	if !strings.Contains(diff, "-two") || !strings.Contains(diff, "+TWO") {
		t.Errorf("the diff does not carry the change:\n%s", diff)
	}
}
