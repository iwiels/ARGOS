package artifact

import (
	"os"
	"strings"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/beautify"
)

func TestExtractIntelligence(t *testing.T) {
	jsCode := `
const API_URL = "/api/v1/users";
const OAUTH_ROUTE = "/oauth/authorize";
fetch('/graphql', { method: 'POST' });
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GOOGLE_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu";
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature";
//# sourceMappingURL=bundle.js.map
`

	intel := Extract(jsCode, beautify.LangJS)

	if len(intel.Endpoints) < 3 {
		t.Fatalf("expected at least 3 endpoints, got %d: %v", len(intel.Endpoints), intel.Endpoints)
	}

	foundGraphql := false
	for _, ep := range intel.Endpoints {
		if ep == "/graphql" {
			foundGraphql = true
		}
	}
	if !foundGraphql {
		t.Errorf("expected to find /graphql in endpoints")
	}

	if len(intel.Secrets) < 3 {
		t.Fatalf("expected at least 3 secrets, got %d: %v", len(intel.Secrets), intel.Secrets)
	}

	if intel.SourceMap != "bundle.js.map" {
		t.Errorf("expected sourceMap 'bundle.js.map', got %q", intel.SourceMap)
	}
}

func TestArtifactStoreSaveAndRead(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "argos-artifacts-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewStore(tempDir)
	meta := &ArtifactMeta{
		ID:           GenerateArtifactID("https://example.com/app.js"),
		Target:       "https://example.com/app.js",
		Host:         "example.com",
		Type:         "javascript",
		OriginalSize: 100,
	}

	jsContent := "line 1: var a = 1;\nline 2: var b = 2;\nline 3: const apiKey = \"secret-token-xyz\";\nline 4: var d = 4;\nline 5: var e = 5;"
	if err := store.Save(meta, jsContent); err != nil {
		t.Fatalf("store.Save failed: %v", err)
	}

	// Read lines
	lines, hasMore, total, err := store.ReadLines(meta.ID, 2, 2)
	if err != nil {
		t.Fatalf("ReadLines failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5 lines, got %d", total)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if lines[0].Number != 2 || !strings.Contains(lines[0].Content, "line 2") {
		t.Errorf("unexpected line 0: %+v", lines[0])
	}
	if !hasMore {
		t.Errorf("expected hasMore == true")
	}

	// Search
	results, err := store.Search(meta.ID, "apiKey", 1)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(results))
	}
	if results[0].MatchLine != 3 {
		t.Errorf("expected match at line 3, got %d", results[0].MatchLine)
	}
}
