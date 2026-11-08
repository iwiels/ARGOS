package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func detectSQLi(client *http.Client, target string, budget time.Duration) []Finding {
	return detectSQLiSpec(client, sqliSpec{URL: target}, budget)
}

func TestCanRunNativeSqliOnlyAfterContainerSuccessful(t *testing.T) {
	tests := []struct {
		name   string
		result *runResult
		want   bool
	}{
		{name: "missing result", want: false},
		{name: "not sandboxed", result: &runResult{ExitCode: 0}, want: false},
		{name: "container failed", result: &runResult{Sandboxed: true, ExitCode: 125}, want: false},
		{name: "container timed out", result: &runResult{Sandboxed: true, ExitCode: 0, TimedOut: true}, want: false},
		{name: "container succeeded", result: &runResult{Sandboxed: true, ExitCode: 0}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canRunNativeSqli(tt.result); got != tt.want {
				t.Fatalf("canRunNativeSqli() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSqlmapOutput(t *testing.T) {
	mockOutput := `
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8871=8871
---
[INFO] the back-end DBMS is SQLite
web server operating system: Linux
back-end DBMS: SQLite
`
	finding, confirmed := parseSqlmapOutput(mockOutput, "http://127.0.0.1:8080/item?id=1")
	if !confirmed {
		t.Fatalf("expected confirmed true, got false")
	}
	if finding.Severity != "critical" {
		t.Fatalf("expected severity critical, got %s", finding.Severity)
	}
	if finding.Title != "SQL Injection Confirmada (sqlmap)" {
		t.Fatalf("unexpected title: %s", finding.Title)
	}
	if finding.CWE != "CWE-89" {
		t.Fatalf("expected CWE-89, got %q", finding.CWE)
	}
	if finding.Confidence != ConfidenceConfirmed {
		t.Fatalf("expected confirmed confidence, got %q", finding.Confidence)
	}
	if finding.CVSS == nil {
		t.Fatal("a sqlmap confirmation must carry the CVSS vector")
	}
}

func TestParseSqlmapOutputNotVulnerable(t *testing.T) {
	mockOutput := `[INFO] all tested parameters do not appear to be injectable`
	_, confirmed := parseSqlmapOutput(mockOutput, "http://127.0.0.1:8080/item?id=1")
	if confirmed {
		t.Fatalf("expected confirmed false for non-vulnerable output")
	}
}

func TestResolveSqliMode(t *testing.T) {
	cases := []struct {
		mode    string
		confirm bool
		impact  bool
		want    string
		wantErr bool
	}{
		{mode: "", want: sqliModeDetect},
		{mode: "detect", want: sqliModeDetect},
		{mode: "confirm", want: sqliModeConfirm},
		{mode: "impact", want: sqliModeImpact},
		{mode: " IMPACT ", want: sqliModeImpact},
		{mode: "", confirm: true, want: sqliModeConfirm},
		{mode: "", impact: true, want: sqliModeImpact},
		{mode: "", confirm: true, impact: true, want: sqliModeImpact},
		{mode: "drop", wantErr: true},
	}
	for _, tc := range cases {
		got, err := resolveSqliMode(tc.mode, tc.confirm, tc.impact)
		if tc.wantErr {
			if err == nil {
				t.Errorf("mode %q: expected an error", tc.mode)
			}
			continue
		}
		if err != nil {
			t.Errorf("mode %q: unexpected error %v", tc.mode, err)
			continue
		}
		if got != tc.want {
			t.Errorf("mode %q: expected %q, got %q", tc.mode, tc.want, got)
		}
	}
}

func TestSimilarity(t *testing.T) {
	if got := similarity("hello world", "hello world"); got != 1 {
		t.Errorf("expected identical texts to score 1, got %v", got)
	}
	if got := similarity("hello world", "totally different body"); got > 0.2 {
		t.Errorf("expected unrelated texts to score low, got %v", got)
	}
	// A rotating token must not move the score much: it is the difference
	// between the old hash based differential and the current one.
	long := "<html><body><p>item 1 item 2 item 3 item 4 item 5 item 6 item 7 item 8 item 9 item 10 " +
		"item 11 item 12 item 13 item 14 item 15</p><input value=\"%s\"></body></html>"
	withToken := fmt.Sprintf(long, "a1b2c3d4")
	otherToken := fmt.Sprintf(long, "ff00aa11")
	if got := similarity(withToken, otherToken); got < 0.85 {
		t.Errorf("expected a rotating token to keep the similarity high, got %v", got)
	}
}

// TestVolatileTokenMasking is the mechanism that keeps a rotating token out
// of the comparison: the token is recognized by its neighbourhood, not by its
// value.
func TestVolatileTokenMasking(t *testing.T) {
	first := "<html><body><input value=\"a1b2c3d4\"><p>item 1</p></body></html>"
	second := "<html><body><input value=\"ff00aa11\"><p>item 1</p></body></html>"
	volatile := volatileTokenKeys(sqliTokens(first), sqliTokens(second))
	if len(volatile) == 0 {
		t.Fatal("expected the rotating token to be detected as volatile")
	}
	normalizedFirst := sqliNormalizeBody(first, "", "", volatile)
	normalizedSecond := sqliNormalizeBody(second, "", "", volatile)
	if normalizedFirst != normalizedSecond {
		t.Fatalf("expected the rotating token to be masked:\n%s\n%s", normalizedFirst, normalizedSecond)
	}
	if got := similarity(normalizedFirst, normalizedSecond); got != 1 {
		t.Errorf("expected the masked bodies to score 1, got %v", got)
	}
}

// TestNonceStripping checks that a reflected value is not a difference: the
// nonce is located in the response and removed before the comparison.
func TestNonceStripping(t *testing.T) {
	nonce := "a1b2c3d4"
	body := "<html><body><p>value: 1" + nonce + "</p></body></html>"
	baseline := "<html><body><p>value: 1</p></body></html>"
	if got := similarity(sqliNormalizeBody(body, "", nonce, nil), sqliNormalizeBody(baseline, "", "", nil)); got != 1 {
		t.Errorf("expected the reflected nonce to be ignored, got %v", got)
	}
}

// TestPayloadNormalization checks that an echoed payload is not a difference:
// a search box that prints the injected value back must not look like a
// differential, and an error page that quotes the payload must not either.
func TestPayloadNormalization(t *testing.T) {
	echoed := "<html><body><p>value: 1' AND '1'='1</p></body></html>"
	baseline := "<html><body><p>value: 1</p></body></html>"
	normalized := sqliNormalizeBody(echoed, sqliBooleanTrue, "", nil)
	if got := similarity(normalized, sqliNormalizeBody(baseline, "", "", nil)); got != 1 {
		t.Errorf("expected the echoed payload to be normalized away, got %v", got)
	}
	escaped := "<html><body><p>value: 1&#39; AND &#39;1&#39;=&#39;1</p></body></html>"
	normalized = sqliNormalizeBody(escaped, sqliBooleanTrue, "", nil)
	if got := similarity(normalized, sqliNormalizeBody(baseline, "", "", nil)); got != 1 {
		t.Errorf("expected the escaped payload to be normalized away, got %v", got)
	}
}

// healthySQLPages are the healthy pages used by the false positive tests: the
// word "sql" appears in every context a real site uses, including the ones
// that a naive "contains sql" detector reports as an injection.
var healthySQLPages = []string{
	"<html><body><footer>Powered by MySQL</footer></body></html>",
	"<html><body><nav><a href=\"/sql\">SQL</a><a href=\"/docs\">Docs</a></nav></body></html>",
	"<html><body><!-- the store runs on PostgreSQL --></body></html>",
	"<html><body><p>Learn SQL in five minutes</p></body></html>",
	"<html><body><p>Our SQL consulting services</p><a href=\"/sql\">SQL</a></body></html>",
	"<html><body><p>value: {{value}}</p><p>Exports to CSV and SQL</p></body></html>",
	"<html><body><nav><a href=\"/sql\">SQL</a></nav><p>value: {{value}}</p></body></html>",
	"<html><body><!-- SELECT * FROM products --></body></html>",
	"<html><body><p>We migrated from MySQL to SQLite3</p></body></html>",
	"<html><body><p>value: {{value}}</p><footer>MySQL</footer></body></html>",
	"<html><body><a href=\"/blog/sql-injection-defense\">SQL injection defense</a></body></html>",
	"<html><body><p>Database: PostgreSQL 16</p><p>value: {{value}}</p></body></html>",
	"<html><body><p>sql</p></body></html>",
	"<html><body><p>SQL</p></body></html>",
	"<html><body><p>value: {{value}}</p><p>sql</p></body></html>",
	"<html><body><header>SQLI</header><p>value: {{value}}</p></body></html>",
	"<html><body><p>Translate to SQL: {{value}}</p></body></html>",
	"<html><body><p>Our stack: MySQL, Redis, PostgreSQL</p><p>value: {{value}}</p></body></html>",
	"<html><body><a href=\"/faq#sql\">sql</a><p>value: {{value}}</p></body></html>",
	"<html><body><p>value: {{value}}</p><p>sqlite3, mysql, oracle</p></body></html>",
}

// healthyServer answers every request with a healthy page that echoes the
// value of the "id" parameter.
func healthyServer(t *testing.T, page string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		body := strings.Replace(page, "{{value}}", r.URL.Query().Get("id"), 1)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestDetectSQLiHealthyPageIsNotReported is the anti false positive test: a
// page that mentions MySQL in its footer is not a SQL injection.
func TestDetectSQLiHealthyPageIsNotReported(t *testing.T) {
	srv := healthyServer(t, healthySQLPages[0])
	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings on a healthy page, got %d: %+v", len(fs), fs)
	}
}

// TestDetectSQLiFalsePositiveRate runs the detector against healthy pages
// that mention "sql" in every context. None of them may be reported.
func TestDetectSQLiFalsePositiveRate(t *testing.T) {
	for i, page := range healthySQLPages {
		srv := healthyServer(t, page)
		fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
		if len(fs) != 0 {
			t.Errorf("page %d: expected 0 findings, got %d: %+v", i, len(fs), fs)
		}
	}
}

// booleanSQLiServer answers with the item list for the tautology and with an
// empty result for the contradiction.
func booleanSQLiServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "' AND '1'='2") {
			_, _ = w.Write([]byte("<html><body><h1>Catalog</h1><p>No results found</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><h1>Catalog</h1><ul><li>Item 1</li><li>Item 2</li><li>Item 3</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDetectSQLiBooleanDifferential(t *testing.T) {
	srv := booleanSQLiServer(t)
	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Confidence != ConfidenceProbable {
		t.Fatalf("expected probable confidence, got %q", f.Confidence)
	}
	if f.Vector != "query:id" {
		t.Fatalf("expected the vector query:id, got %q", f.Vector)
	}
	if f.CVSS != nil {
		t.Error("a probable finding must not carry a CVSS vector")
	}
	if f.Evidence["surface"] != "query" {
		t.Errorf("expected the query surface in the evidence, got %v", f.Evidence["surface"])
	}
}

func TestDetectSQLiErrorMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html><body><b>Warning</b>: mysql_fetch_array() expects: 1 parameter, 2 given in /var/www/db.php on line 12</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><h1>Catalog</h1><ul><li>Item 1</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Confidence != ConfidenceConfirmed {
		t.Fatalf("expected confirmed confidence, got %q", f.Confidence)
	}
	if f.CVSS == nil {
		t.Error("a confirmed finding must carry the CVSS vector")
	}
	markers, _ := f.Evidence["markers"].([]string)
	if len(markers) < 2 {
		t.Fatalf("expected at least two error markers, got %v", markers)
	}
}

func TestDetectSQLiTimeBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.Query().Get("id")), "sleep(") {
			time.Sleep(3 * time.Second)
		}
		_, _ = w.Write([]byte("<html><body><h1>Catalog</h1><ul><li>Item 1</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 60*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Confidence != ConfidenceConfirmed {
		t.Fatalf("expected confirmed confidence, got %q", f.Confidence)
	}
	delta, _ := f.Evidence["time_delta_ms"].(int64)
	if delta <= 2000 {
		t.Fatalf("expected a time delta over 2000ms, got %d", delta)
	}
}

func TestDetectSQLiRotatingTokenKeepsTheDifferential(t *testing.T) {
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		token := fmt.Sprintf("%08x", n*2654435761)
		var body string
		if strings.Contains(r.URL.Query().Get("id"), "' AND '1'='2") {
			body = "<ul><li>No items</li></ul>"
		} else {
			body = "<ul><li>Item 1</li><li>Item 2</li><li>Item 3</li></ul>"
		}
		fmt.Fprintf(w, "<html><body><input type=\"hidden\" name=\"csrf\" value=\"%s\">%s</body></html>", token, body)
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Confidence != ConfidenceProbable {
		t.Fatalf("expected probable confidence, got %q", fs[0].Confidence)
	}
}

func TestDetectSQLiPostBodySurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user := r.FormValue("username")
		if strings.Contains(user, "' AND '1'='2") {
			_, _ = w.Write([]byte("<html><body><p>Unknown user</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>Welcome, admin</p><ul><li>Panel</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLiSpec(srv.Client(), sqliSpec{
		URL:    srv.URL,
		Method: http.MethodPost,
		Body:   "username=admin&password=secret",
	}, 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Vector != "body:username" {
		t.Fatalf("expected the vector body:username, got %q", fs[0].Vector)
	}
	if fs[0].Evidence["surface"] != "body" {
		t.Fatalf("expected the body surface in the evidence, got %v", fs[0].Evidence["surface"])
	}
}

func TestDetectSQLiJSONBodySurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var doc map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &doc)
		user, _ := doc["username"].(string)
		if strings.Contains(user, "' AND '1'='2") {
			_, _ = w.Write([]byte("<html><body><p>Unknown user</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>Welcome, admin</p><ul><li>Panel</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLiSpec(srv.Client(), sqliSpec{
		URL:    srv.URL,
		Method: http.MethodPost,
		Body:   `{"username":"admin","password":"secret"}`,
	}, 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Vector != "json:username" {
		t.Fatalf("expected the vector json:username, got %q", fs[0].Vector)
	}
}

func TestDetectSQLiHeaderSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.Header.Get("X-Forwarded-For")
		if strings.Contains(ip, "' AND '1'='2") {
			_, _ = w.Write([]byte("<html><body><p>Blocked</p></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><p>Welcome</p><ul><li>Panel</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLiSpec(srv.Client(), sqliSpec{
		URL:      srv.URL + "?id=1",
		Surfaces: []string{"header"},
	}, 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Vector != "header:X-Forwarded-For" {
		t.Fatalf("expected the vector header:X-Forwarded-For, got %q", fs[0].Vector)
	}
	if fs[0].Evidence["surface"] != "header" {
		t.Fatalf("expected the header surface in the evidence, got %v", fs[0].Evidence["surface"])
	}
}

func TestDetectSQLiFindingContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html><body><b>Warning</b>: mysql_fetch_array() expects: 1 parameter, 2 given in /var/www/db.php on line 12</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><h1>Catalog</h1><ul><li>Item 1</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Source != "web.sqli" || f.SourceTool != "web.sqli" {
		t.Errorf("unexpected source: %q / %q", f.Source, f.SourceTool)
	}
	if f.CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", f.CWE)
	}
	if len(f.Tags) != 1 || f.Tags[0] != "sqli" {
		t.Errorf("expected the tag sqli, got %v", f.Tags)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected a critical severity, got %q", f.Severity)
	}
	for _, key := range []string{"surface", "parameter", "baseline_status", "reflected_offset", "similarity_true", "similarity_false", "similarity_baseline", "time_delta_ms", "markers", "payloads", "method"} {
		if _, ok := f.Evidence[key]; !ok {
			t.Errorf("missing evidence key %q", key)
		}
	}
	payloads, _ := f.Evidence["payloads"].([]string)
	if !slices.Contains(payloads, sqliBooleanTrue) || !slices.Contains(payloads, sqliBooleanFalse) {
		t.Errorf("expected the boolean payloads in the evidence, got %v", payloads)
	}
	if f.Evidence["method"] != http.MethodGet {
		t.Errorf("expected the GET method in the evidence, got %v", f.Evidence["method"])
	}
	// The server of this test does not echo the value back, so there is no
	// reflected offset to report.
	if offset, _ := f.Evidence["reflected_offset"].(int); offset != -1 {
		t.Errorf("expected a reflected offset of -1, got %v", f.Evidence["reflected_offset"])
	}
}

// TestDetectSQLiRecordsTheReflectedOffset checks that the nonce is located
// in the response of a server that echoes the value back.
func TestDetectSQLiRecordsTheReflectedOffset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		body := "<html><body><p>value: " + q + "</p>"
		if strings.Contains(q, "' AND '1'='2") {
			body += "<p>no items</p></body></html>"
		} else {
			body += "<ul><li>item 1</li><li>item 2</li></ul></body></html>"
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	offset, _ := fs[0].Evidence["reflected_offset"].(int)
	if offset < 0 {
		t.Fatalf("expected a reflected offset, got %v", fs[0].Evidence["reflected_offset"])
	}
}

// sqliPocOf returns the proof of concept of a finding as it crosses the wire:
// the JSON shape the backend receives.
func sqliPocOf(t *testing.T, f Finding) map[string]any {
	t.Helper()
	raw, err := json.Marshal(f.ToMap())
	if err != nil {
		t.Fatalf("cannot encode the finding: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("cannot decode the finding: %v", err)
	}
	evidence, ok := decoded["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("expected an evidence object, got %v", decoded["evidence"])
	}
	poc, ok := evidence["poc"].(map[string]any)
	if !ok {
		t.Fatalf("expected a poc in the evidence, got %v", evidence)
	}
	return poc
}

// TestDetectSQLiFindingCarriesThePoc checks that the SQLi finding ships the
// proof of concept: the request that reproduces it and the matcher that
// decides whether it still reproduces.
func TestDetectSQLiFindingCarriesThePoc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		body := "<html><body><p>value: " + q + "</p>"
		if strings.Contains(q, "' AND '1'='2") {
			body += "<p>no items</p></body></html>"
		} else {
			body += "<ul><li>item 1</li><li>item 2</li></ul></body></html>"
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}

	poc := sqliPocOf(t, fs[0])
	if poc["kind"] != "sqli" {
		t.Errorf("expected the sqli kind, got %v", poc["kind"])
	}
	if poc["method"] != http.MethodGet {
		t.Errorf("expected the GET method, got %v", poc["method"])
	}
	rawURL, _ := poc["url"].(string)
	if !strings.Contains(rawURL, "id=") {
		t.Errorf("expected the replay URL to carry the parameter, got %q", rawURL)
	}
	payload, _ := poc["payload"].(string)
	if payload == "" {
		t.Error("expected the payload in the poc")
	}

	matcher, ok := poc["matcher"].(map[string]any)
	if !ok {
		t.Fatalf("expected a matcher in the poc, got %v", poc["matcher"])
	}
	// The server echoes the payload, so the needle check is the precise one.
	if matcher["kind"] != "body_absent" {
		t.Errorf("expected the body_absent matcher, got %v", matcher["kind"])
	}
	if matcher["needle"] != payload {
		t.Errorf("expected the payload as the needle, got %v", matcher["needle"])
	}

	baseline, ok := poc["baseline"].(map[string]any)
	if !ok {
		t.Fatalf("expected a baseline in the poc, got %v", poc["baseline"])
	}
	if status, _ := baseline["status"].(float64); status == 0 {
		t.Errorf("expected the baseline status, got %v", baseline["status"])
	}
	digest, _ := baseline["bodyDigest"].(string)
	if len(digest) != 64 {
		t.Errorf("expected a sha256 digest in the baseline, got %q", digest)
	}
	if snippet, _ := baseline["bodySnippet"].(string); snippet == "" {
		t.Error("expected the body snippet in the baseline")
	}
}

// TestDetectSQLiPocComparesTheResponseWhenThePayloadIsNotEchoed covers the
// differential that does not reflect the payload: there the symptom is the
// shape of the response, so the matcher compares it with the original one.
func TestDetectSQLiPocComparesTheResponseWhenThePayloadIsNotEchoed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html><body><b>Warning</b>: mysql_fetch_array() expects: 1 parameter, 2 given</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><h1>Catalog</h1><ul><li>Item 1</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	poc := sqliPocOf(t, fs[0])
	matcher, _ := poc["matcher"].(map[string]any)
	if matcher["kind"] != "body_changed" {
		t.Errorf("expected the body_changed matcher, got %v", matcher["kind"])
	}
}

// TestDetectSQLiTimeBasedCarriesTheTimingMatcher checks that a time based
// injection is re-tested against the clock, not against the body.
func TestDetectSQLiTimeBasedCarriesTheTimingMatcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.Query().Get("id")), "sleep(") {
			time.Sleep(3 * time.Second)
		}
		_, _ = w.Write([]byte("<html><body><h1>Catalog</h1><ul><li>Item 1</li></ul></body></html>"))
	}))
	t.Cleanup(srv.Close)

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 60*time.Second)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	poc := sqliPocOf(t, fs[0])
	matcher, _ := poc["matcher"].(map[string]any)
	if matcher["kind"] != "timing_under" {
		t.Fatalf("expected the timing_under matcher, got %v", matcher["kind"])
	}
	ms, _ := matcher["ms"].(float64)
	if ms <= 0 {
		t.Errorf("expected a threshold in the timing matcher, got %v", matcher["ms"])
	}
}
