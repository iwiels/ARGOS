package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

func newMockES(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

func TestDoUsesApiKeyAuth(t *testing.T) {
	var authHeader string
	srv, _ := newMockES(t, func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	client := NewClient(&Config{BaseURL: srv.URL, APIKey: "dG9rZW4="})

	_, errObj := client.Do(context.Background(), "GET", "/", nil)
	if errObj != nil {
		t.Fatalf("unexpected error: %v", errObj.Message)
	}
	if authHeader != "ApiKey dG9rZW4=" {
		t.Fatalf("expected ApiKey auth header, got %q", authHeader)
	}
}

func TestDoUsesBasicAuth(t *testing.T) {
	var authHeader string
	srv, _ := newMockES(t, func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	client := NewClient(&Config{BaseURL: srv.URL, User: "admin", Password: "secret"})

	_, errObj := client.Do(context.Background(), "GET", "/", nil)
	if errObj != nil {
		t.Fatalf("unexpected error: %v", errObj.Message)
	}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	if authHeader != expected {
		t.Fatalf("expected basic auth header %q, got %q", expected, authHeader)
	}
}

func TestDoBuildsPathAndParsesJSON(t *testing.T) {
	var seenPath string
	srv, _ := newMockES(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":{"number":"8.15.0"}}`)
	})
	client := NewClient(&Config{BaseURL: srv.URL + "/es-proxy", APIKey: "x"})

	result, errObj := client.Do(context.Background(), "GET", "/_cat/indices?format=json", nil)
	if errObj != nil {
		t.Fatalf("unexpected error: %v", errObj.Message)
	}
	if seenPath != "/es-proxy/_cat/indices?format=json" {
		t.Fatalf("unexpected request path %q", seenPath)
	}
	parsed, ok := result.(map[string]interface{})
	if !ok || parsed["version"] == nil {
		t.Fatalf("expected parsed JSON result, got %#v", result)
	}
}

func TestDoMapsHTTPErrors(t *testing.T) {
	srv, _ := newMockES(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"type":"search_phase_execution_exception"}}`)
	})
	client := NewClient(&Config{BaseURL: srv.URL, APIKey: "x"})

	_, errObj := client.Do(context.Background(), "GET", "/", nil)
	if errObj == nil {
		t.Fatal("expected an error object")
	}
	if !strings.Contains(errObj.Message, "HTTP 400") {
		t.Fatalf("expected HTTP status in error, got %q", errObj.Message)
	}
}

func TestDoReportsMissingConfig(t *testing.T) {
	client := NewClient(&Config{})
	_, errObj := client.Do(context.Background(), "GET", "/", nil)
	if errObj == nil {
		t.Fatal("expected an error object")
	}
	if !strings.Contains(errObj.Message, "ARGOS_ES_URL") {
		t.Fatalf("expected config guidance in error, got %q", errObj.Message)
	}
}

func TestSortParam(t *testing.T) {
	specs := map[string]string{
		"@timestamp:desc": `[{"@timestamp":"desc"}]`,
		"score":           `[{"score":"asc"}]`,
		"field:DESC":      `[{"field":"desc"}]`,
		"a:b:c":           `[{"a":"asc"}]`,
	}
	for spec, want := range specs {
		got, err := json.Marshal(sortParam(spec))
		if err != nil {
			t.Fatalf("marshal %q: %v", spec, err)
		}
		if string(got) != want {
			t.Errorf("sortParam(%q) = %s, want %s", spec, got, want)
		}
	}
}

// TestSearchRoundtrip drives es.search through the MCP server against a mock
// Elasticsearch, verifying the request path, query DSL body and response.
func TestSearchRoundtrip(t *testing.T) {
	var seenBody map[string]interface{}
	var seenPath string
	srv, _ := newMockES(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.String()
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &seenBody)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"hits":{"total":{"value":1},"hits":[{"_source":{"message":"boom"}}]}}`)
	})

	requests := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"es.search","arguments":{"index":"logs-*","query":"{\"query\":{\"match\":{\"level\":\"error\"}}}","size":"5"}}}` + "\n"

	var out bytes.Buffer
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "test", Version: "1"}, strings.NewReader(requests), &out)
	env := &Env{Client: NewClient(&Config{BaseURL: srv.URL, APIKey: "x"})}
	RegisterAll(server, env)
	if err := server.Run(context.Background()); err != nil {
		t.Fatalf("server run: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for seenPath == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if seenPath != "/logs-%2A/_search" && seenPath != "/logs-*/_search" {
		t.Fatalf("unexpected search path %q", seenPath)
	}
	query, ok := seenBody["query"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected query in body, got %#v", seenBody)
	}
	match := query["match"].(map[string]interface{})
	if match["level"] != "error" {
		t.Fatalf("expected match level=error, got %#v", match)
	}
	if seenBody["size"] != float64(5) {
		t.Fatalf("expected size 5, got %#v", seenBody["size"])
	}
	// The tool result text is itself a JSON string embedded in the MCP
	// envelope, so its quotes come back escaped (\"message\":\"boom\") in the
	// raw transport bytes — decode the envelope and check the unwrapped text.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &envelope); err != nil {
		t.Fatalf("decode MCP response: %v (raw: %q)", err, out.String())
	}
	if len(envelope.Result.Content) == 0 || !strings.Contains(envelope.Result.Content[0].Text, `"message":"boom"`) {
		t.Fatalf("expected search result in MCP response, got %q", out.String())
	}
}
