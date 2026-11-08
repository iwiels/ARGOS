package beautify

import (
	"strings"
	"testing"
)

func TestFormatJSON(t *testing.T) {
	minified := `{"name":"argos","version":1,"endpoints":["/api/v1","/auth"]}`
	formatted, err := FormatJSON(minified)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	if !strings.Contains(formatted, "  \"name\": \"argos\"") {
		t.Errorf("expected indented JSON, got:\n%s", formatted)
	}
}

func TestFormatJS(t *testing.T) {
	minified := `function login(u,p){const token=fetch('/api/login',{body:JSON.stringify({u,p})});return token;}`
	formatted, err := FormatJS(minified)
	if err != nil {
		t.Fatalf("FormatJS failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(formatted), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines for formatted JS, got %d:\n%s", len(lines), formatted)
	}
	if !strings.Contains(formatted, "const token = fetch('/api/login'") && !strings.Contains(formatted, "fetch('/api/login'") {
		t.Errorf("expected clean statement, got:\n%s", formatted)
	}
}

func TestFormatCSS(t *testing.T) {
	minified := `body{margin:0;padding:0;background:#121212;}.header{color:#10b981;font-size:14px;}`
	formatted, err := FormatCSS(minified)
	if err != nil {
		t.Fatalf("FormatCSS failed: %v", err)
	}
	if !strings.Contains(formatted, "  margin: 0;") {
		t.Errorf("expected indented CSS property, got:\n%s", formatted)
	}
}

func TestFormatHTMLWithNestedScript(t *testing.T) {
	minified := `<!DOCTYPE html><html><head><title>Test</title><style>body{color:#fff;}</style></head><body><div class="main"><h1>Hello</h1><script>var x=1;var y=2;</script></div></body></html>`
	formatted, err := FormatHTML(minified)
	if err != nil {
		t.Fatalf("FormatHTML failed: %v", err)
	}

	if !strings.Contains(formatted, "<script>") || !strings.Contains(formatted, "var x = 1;") {
		t.Errorf("expected nested JS to be formatted inside HTML, got:\n%s", formatted)
	}
}

func TestDetectLanguage(t *testing.T) {
	if DetectLanguage("https://example.com/bundle.min.js?v=1", "") != LangJS {
		t.Errorf("expected LangJS")
	}
	if DetectLanguage("index.html", "") != LangHTML {
		t.Errorf("expected LangHTML")
	}
	if DetectLanguage("style.css", "") != LangCSS {
		t.Errorf("expected LangCSS")
	}
	if DetectLanguage("api.json", "") != LangJSON {
		t.Errorf("expected LangJSON")
	}
	if DetectLanguage("unknown", `{"valid":"json"}`) != LangJSON {
		t.Errorf("expected LangJSON by content sniffing")
	}
}
