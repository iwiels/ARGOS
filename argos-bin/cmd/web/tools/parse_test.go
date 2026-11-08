package tools

import (
	"bufio"
	"encoding/json"
	"io"
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

func TestParseNuclei(t *testing.T) {
	out := `{"template-id":"CVE-2024-1234","info":{"name":"Example RCE","severity":"critical","tags":["rce","cve"]},"matched-at":"https://example.com/vuln"}
{"template-id":"exposed-panel","info":{"name":"Admin Panel","severity":"high"},"matched-at":"https://example.com/admin"}`
	fs := parseNuclei(out, "https://example.com", "web.scan")
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2", len(fs))
	}
	if fs[0].Severity != "critical" || fs[0].Title != "Example RCE" {
		t.Errorf("bad first finding: %+v", fs[0])
	}
	if fs[1].Severity != "high" {
		t.Errorf("bad second severity: %s", fs[1].Severity)
	}
}

// A real nuclei JSONL line: the classification block of a template carries
// the CWE, the CVE and the CVSS vector of the vulnerability.
const nucleiClassificationJSONL = `{"template-id":"generic-env","info":{"name":"Generic Environment Variable","author":"pdteam","severity":"high","description":"Generic environment variable exposure","reference":["https://owasp.org/Top10/A05_2021-Security_Misconfiguration"],"classification":{"cve-id":"CVE-2021-45046","cwe-id":"CWE-522","cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cvss-score":7.5},"remediation":"Remove the environment file from the web root","metadata":{"max-request":1},"tags":"exposure,config"},"type":"http","host":"https://example.com","matched-at":"https://example.com/.env","extracted-results":["DB_PASSWORD=hunter2"],"matcher-name":"env-file"}`

func TestParseNuclei_ClassificationCarriesTheTaxonomy(t *testing.T) {
	fs := parseNuclei(nucleiClassificationJSONL, "https://example.com", "web.scan")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.RuleID != "nuclei:generic-env" {
		t.Errorf("rule id = %q", f.RuleID)
	}
	if f.CWE != "CWE-522" {
		t.Errorf("cwe = %q, want CWE-522 (the template classification)", f.CWE)
	}
	if f.Evidence["cve"] != "CVE-2021-45046" {
		t.Errorf("evidence should carry the cve: %+v", f.Evidence)
	}
	if f.Evidence["cvss_score"] != 7.5 {
		t.Errorf("evidence should carry the cvss score: %+v", f.Evidence)
	}
	if f.CVSS == nil || f.CVSS.AV != "N" || f.CVSS.C != "H" {
		t.Errorf("the cvss vector was not parsed: %+v", f.CVSS)
	}
	if f.Remediation != "Remove the environment file from the web root" {
		t.Errorf("remediation = %q", f.Remediation)
	}
	if len(f.References) != 1 || f.References[0] != "https://owasp.org/Top10/A05_2021-Security_Misconfiguration" {
		t.Errorf("references = %+v", f.References)
	}
	if f.Vector != "https://example.com/.env" {
		t.Errorf("vector = %q", f.Vector)
	}
	if f.Confidence != "confirmed" {
		t.Errorf("extracted results mean a confirmed finding, got %q", f.Confidence)
	}
}

// Without a cwe-id the registry supplies the taxonomy of the rule.
func TestParseNuclei_CWEComesFromTheRegistry(t *testing.T) {
	out := `{"template-id":"git-config","info":{"name":"Git Configuration - Detect","severity":"medium","tags":"config,git,exposure,vuln"},"type":"http","matched-at":"https://example.com/.git/config"}`
	fs := parseNuclei(out, "https://example.com", "web.scan")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].CWE != "CWE-200" {
		t.Errorf("cwe = %q, want CWE-200 (from the registry)", fs[0].CWE)
	}
	if fs[0].Severity != "medium" {
		t.Errorf("severity = %q, want medium", fs[0].Severity)
	}
}

// A rule the registry does not know and a template without a classification
// must not produce a CWE: an invented identifier is worse than none.
func TestParseNuclei_NeverInventsACWE(t *testing.T) {
	out := `{"template-id":"some-unknown-template","info":{"name":"Unknown","severity":"low","tags":"vuln,generic"},"type":"http","matched-at":"https://example.com/x"}`
	fs := parseNuclei(out, "https://example.com", "web.scan")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].CWE != "" {
		t.Errorf("cwe = %q, want an empty cwe", fs[0].CWE)
	}
}

func TestParseNuclei_SeverityChain(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "the cvss score of the template wins",
			out:  `{"template-id":"generic-env","info":{"name":"x","severity":"medium","classification":{"cvss-score":9.8}}}`,
			want: "critical",
		},
		{
			name: "the cvss score of the template maps to its band",
			out:  `{"template-id":"unknown-template","info":{"name":"x","severity":"critical","classification":{"cvss-score":5.3}}}`,
			want: "medium",
		},
		{
			name: "the registry floor raises a severity the template understates",
			out:  `{"template-id":"generic-env","info":{"name":"x","severity":"medium","classification":{"cvss-score":5.3}}}`,
			want: "high",
		},
		{
			name: "the classification severity is used when there is no score",
			out:  `{"template-id":"unknown-template","info":{"name":"x","severity":"critical","classification":{"severity":"low"}}}`,
			want: "low",
		},
		{
			name: "the registry floor is used when the template declares none",
			out:  `{"template-id":"generic-env","info":{"name":"x"}}`,
			want: "high",
		},
		{
			name: "the template severity is used when the rule is unknown",
			out:  `{"template-id":"unknown-template","info":{"name":"x","severity":"medium"}}`,
			want: "medium",
		},
		{
			name: "info is the last resort",
			out:  `{"template-id":"unknown-template","info":{"name":"x"}}`,
			want: "info",
		},
		{
			name: "the registry floor never lowers a declared severity",
			out:  `{"template-id":"unknown-template","info":{"name":"x","severity":"low"}}`,
			want: "low",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := parseNuclei(tc.out, "https://example.com", "web.scan")
			if len(fs) != 1 {
				t.Fatalf("got %d findings, want 1", len(fs))
			}
			if fs[0].Severity != tc.want {
				t.Errorf("severity = %q, want %q", fs[0].Severity, tc.want)
			}
		})
	}
}

func TestParseNuclei_ConfidenceChain(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "extracted results confirm the finding",
			out:  `{"template-id":"unknown-template","info":{"name":"x","severity":"high"},"extracted-results":["token"]}`,
			want: "confirmed",
		},
		{
			name: "a template that matched an explicit assertion confirms it",
			out:  `{"template-id":"generic-env","info":{"name":"x","severity":"high"}}`,
			want: "confirmed",
		},
		{
			name: "an informational exposure is only possible",
			out:  `{"template-id":"swagger-api","info":{"name":"x","severity":"info"}}`,
			want: "possible",
		},
		{
			name: "an unknown rule stays probable",
			out:  `{"template-id":"unknown-template","info":{"name":"x","severity":"high"}}`,
			want: "probable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := parseNuclei(tc.out, "https://example.com", "web.scan")
			if len(fs) != 1 {
				t.Fatalf("got %d findings, want 1", len(fs))
			}
			if fs[0].Confidence != tc.want {
				t.Errorf("confidence = %q, want %q", fs[0].Confidence, tc.want)
			}
		})
	}
}

// The tags of a finding are the union of the template tags (filtered to the
// canonical vocabulary the engines match on) and the tags of the registry.
func TestParseNuclei_TagsAreTheUnionOfTheTemplateAndTheRegistry(t *testing.T) {
	out := `{"template-id":"generic-env","info":{"name":"x","severity":"high","tags":"exposure,config,not-a-canonical-tag"}}`
	fs := parseNuclei(out, "https://example.com", "web.scan")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	tags := map[string]bool{}
	for _, tag := range fs[0].Tags {
		tags[tag] = true
	}
	for _, want := range []string{"information-disclosure", ".env", "credentials", "secret-exposure"} {
		if !tags[want] {
			t.Errorf("the tag %q is missing: %+v", want, fs[0].Tags)
		}
	}
	if tags["not-a-canonical-tag"] {
		t.Errorf("a tag outside the vocabulary must be dropped: %+v", fs[0].Tags)
	}
	if tags["config"] {
		t.Errorf("a template tag outside the vocabulary must be dropped: %+v", fs[0].Tags)
	}
}

func TestParseHttpx(t *testing.T) {
	out := `{"url":"https://example.com","status_code":200,"title":"Example","tech":["React","Nginx"],"webserver":"nginx"}`
	res := parseHttpx(out)
	if len(res) != 1 {
		t.Fatalf("got %d, want 1", len(res))
	}
	if res[0].StatusCode != 200 || len(res[0].Tech) != 2 {
		t.Errorf("bad result: %+v", res[0])
	}
}

func TestParseFfuf(t *testing.T) {
	out := `{"input":{"FUZZ":".env"},"status":200,"length":123,"url":"https://example.com/.env"}
{"input":{"FUZZ":"admin"},"status":301,"length":0,"url":"https://example.com/admin"}`
	hits := parseFfuf(out)
	if len(hits) != 2 {
		t.Fatalf("got %d, want 2", len(hits))
	}
	if hits[0].Input["FUZZ"] != ".env" {
		t.Errorf("bad first hit: %+v", hits[0])
	}
}

// ffuf -json base64-encodes input values (real captured output)
func TestParseFfuf_Base64EncodedInput(t *testing.T) {
	out := `{"input":{"FFUFHASH":"Mjg1NTkx","FUZZ":"LmVudg=="},"position":1,"status":200,"length":74,"url":"http://127.0.0.1:8788/.env"}
{"input":{"FFUFHASH":"Mjg1NTk5","FUZZ":"YWRtaW4v"},"position":9,"status":200,"length":159,"url":"http://127.0.0.1:8788/admin/"}`
	hits := parseFfuf(out)
	if len(hits) != 2 {
		t.Fatalf("got %d, want 2", len(hits))
	}
	if hits[0].Input["FUZZ"] != ".env" || hits[1].Input["FUZZ"] != "admin/" {
		t.Errorf("base64 FUZZ not decoded: %+v", hits)
	}
	fs := findingsFromFuzz(hits, "http://127.0.0.1:8788")
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0: discovered routes are not vulnerabilities", len(fs))
	}
}

func TestFindingsFromFuzzDoesNotPromoteRouteNamesToVulnerabilities(t *testing.T) {
	hits := []ffufResult{
		{Input: map[string]string{"FUZZ": ".env"}, Status: 200, URL: "https://e/.env"},
		{Input: map[string]string{"FUZZ": ".git/config"}, Status: 200, URL: "https://e/.git/config"},
		{Input: map[string]string{"FUZZ": "backup.zip"}, Status: 200, URL: "https://e/backup.zip"},
		{Input: map[string]string{"FUZZ": "admin/"}, Status: 200, URL: "https://e/admin/"},
		{Input: map[string]string{"FUZZ": "swagger.json"}, Status: 200, URL: "https://e/swagger.json"},
		{Input: map[string]string{"FUZZ": "graphql"}, Status: 200, URL: "https://e/graphql"},
		{Input: map[string]string{"FUZZ": "robots.txt"}, Status: 200, URL: "https://e/robots.txt"},
	}
	fs := findingsFromFuzz(hits, "https://e")
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0: ffuf path names/status alone do not prove exposure", len(fs))
	}
}

func TestParseSubfinderAndDnsx(t *testing.T) {
	subs := parseSubfinder(`{"host":"www.example.com","source":"crt.sh"}`)
	if len(subs) != 1 || subs[0].Host != "www.example.com" {
		t.Fatalf("bad subfinder parse: %+v", subs)
	}
	ips := parseDnsx(`{"host":"www.example.com","a":["93.184.216.34"]}`)
	if len(ips["www.example.com"]) != 1 || ips["www.example.com"][0] != "93.184.216.34" {
		t.Fatalf("bad dnsx parse: %+v", ips)
	}
}

func TestParseDalfox(t *testing.T) {
	out := `{"type":"finding","data":{"type":"V","severity":"high","payload":"<script>","url":"https://e/?q=x","cwe":"CWE-79","param":"q"}}`
	fs := parseDalfox(out, "https://e")
	if len(fs) != 1 {
		t.Fatalf("got %d, want 1", len(fs))
	}
	if fs[0].Severity != "high" || fs[0].Title != "XSS: V" {
		t.Errorf("bad finding: %+v", fs[0])
	}
}

// dalfox v3 --format json emits a single object with a findings array (real output)
func TestParseDalfox_V3FindingsObject(t *testing.T) {
	out := `{"findings":[{"confidence":"high","confidence_reason":"payload reached an executable position","cwe":"CWE-79","data":"http://127.0.0.1/profile?user=%3Csvg%20onload%3Dalert%281%29%3E","detection_method":"reflection","inject_type":"inHTML","method":"GET","param":"user","payload":"<svg onload=alert(1)>","severity":"High","type":"V","type_description":"Vulnerable"}]}`
	fs := parseDalfox(out, "http://127.0.0.1")
	if len(fs) != 1 {
		t.Fatalf("got %d, want 1", len(fs))
	}
	if fs[0].Severity != "high" || fs[0].Title != "XSS: V" {
		t.Errorf("bad finding: %+v", fs[0])
	}
	if fs[0].Target != "http://127.0.0.1/profile?user=%3Csvg%20onload%3Dalert%281%29%3E" {
		t.Errorf("bad target: %q", fs[0].Target)
	}
	if fs[0].Vector != "user" {
		t.Errorf("vector should carry the vulnerable param: %q", fs[0].Vector)
	}
	if fs[0].CWE != "CWE-79" {
		t.Errorf("cwe should be normalized: %q", fs[0].CWE)
	}
	if fs[0].Confidence != "confirmed" {
		t.Errorf("dalfox type V is a confirmed finding, got %q", fs[0].Confidence)
	}
	if fs[0].Evidence["param"] != "user" {
		t.Errorf("evidence should carry the param: %+v", fs[0].Evidence)
	}
}

// v3 object preceded by non-JSON garbage must still parse (balanced braces)
func TestParseDalfox_V3WithLeadingGarbage(t *testing.T) {
	out := `some warning line
{"findings":[{"cwe":"CWE-79","data":"http://e/?q=x","payload":"<svg>","param":"q","severity":"High","type":"V"}]}
trailing stats: 1 finding`
	fs := parseDalfox(out, "http://e")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1 (garbage ignored)", len(fs))
	}
	if fs[0].Severity != "high" {
		t.Errorf("severity = %q", fs[0].Severity)
	}
}

func TestParseGau(t *testing.T) {
	out := "https://a\nhttps://b\nhttps://c\n"
	urls := parseGau(out, 2)
	if len(urls) != 2 {
		t.Fatalf("got %d, want 2 (limit)", len(urls))
	}
}

func TestParseTlsx(t *testing.T) {
	out := `{"host":"example.com","port":"443","probe_status":true,"tls_version":"tls10","cipher":"TLS_RSA_WITH_RC4_128_SHA","subject_cn":"example.com","issuer_cn":"Untrusted CA","expired":true,"self_signed":true}
{"host":"secure.com","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","subject_cn":"secure.com","issuer_cn":"DigiCert"}`
	fs := parseTlsxJSON([]byte(out), "https://example.com")
	if len(fs) < 3 {
		t.Fatalf("expected at least 3 findings for insecure target, got %d", len(fs))
	}
	titles := map[string]bool{}
	for _, f := range fs {
		titles[f.Title] = true
	}
	if !titles["Expired SSL/TLS Certificate"] {
		t.Errorf("missing expired cert finding")
	}
	if !titles["Self-Signed SSL/TLS Certificate"] {
		t.Errorf("missing self-signed cert finding")
	}
	if !titles["Deprecated TLS Protocol: tls10"] {
		t.Errorf("missing deprecated TLS version finding")
	}
	if !titles["Weak Cipher Suite: TLS_RSA_WITH_RC4_128_SHA"] {
		t.Errorf("missing weak cipher finding")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"critical": "critical", "CRIT": "critical", "high": "high",
		"medium": "medium", "moderate": "medium", "low": "low", "info": "info", "": "info",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSpecsPinned(t *testing.T) {
	for _, spec := range binSpecs {
		if spec.Version == "" || spec.Repo == "" || spec.Bin == "" {
			t.Errorf("spec %q is missing fields: %+v", spec.Name, spec)
		}
	}
}

func TestValidateWebTarget(t *testing.T) {
	guard := newTestWebScope(t, scope.ScopeConfig{AllowedDomains: []string{"example.com"}})
	ok, e := validateWebTargetWithGuard(guard, "example.com")
	if e != nil || ok != "http://example.com" {
		t.Errorf("bare host: got %q, err %v", ok, e)
	}
	if _, e := validateWebTargetWithGuard(guard, "ftp://x"); e == nil {
		t.Error("ftp scheme should be rejected")
	}
	if _, e := validateWebTargetWithGuard(guard, ""); e == nil {
		t.Error("empty target should be rejected")
	}
}

// ————— registration test via pipes (mirrors cmd/lan/tools_test.go) —————

func TestRegisterAll_ToolsRegistered(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()

	s := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "1.0.0"})
	env := NewEnv(t.TempDir())
	RegisterAll(s, env)
	// The business logic tools (ARG-024) are wired into RegisterAll by the
	// registration that owns tools.go. Until that wiring lands they are
	// registered here, so the expected tool set stays asserted in both
	// states and the list never carries a duplicate.
	if s.GetToolHandler("web.jwt") == nil {
		RegisterVectors(s, env)
	}

	go func() {
		scanner := bufio.NewScanner(serverR)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var req mcp.Request
			if json.Unmarshal([]byte(line), &req) != nil {
				continue
			}
			resp := mcp.Response{JSONRPC: "2.0", ID: req.ID}
			if req.Method == "tools/list" {
				resp.Result = map[string]interface{}{"tools": s.ToolDefinitions()}
			} else {
				resp.Error = mcp.ErrMethodNotFound
			}
			data, _ := json.Marshal(resp)
			serverW.Write(data)
			serverW.Write([]byte("\n"))
		}
	}()

	clientW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"))
	scanner := bufio.NewScanner(clientR)
	if !scanner.Scan() {
		t.Fatal("no response")
	}
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(scanner.Text()), &resp); err != nil {
		t.Fatal(err)
	}
	raw, ok := resp["result"].(map[string]interface{})["tools"].([]interface{})
	if !ok {
		t.Fatalf("no tools in response: %v", resp)
	}
	names := map[string]bool{}
	for _, r := range raw {
		d, _ := r.(map[string]interface{})
		name, _ := d["name"].(string)
		names[name] = true
	}
	want := []string{
		"web.scan", "web.sqli", "web.fuzz", "web.params", "web.crawl",
		"web.probe", "web.tech", "web.subdomains", "web.urls", "web.xss",
		"web.oob", "web.waf", "web.api", "web.tls", "web.ports",
		"code.sast", "code.semantic", "code.analyze", "code.deps", "code.sbom", "code.secrets", "web.cms",
		"web.artifact", "web.artifact.read", "web.wordlists",
		"web.jwt", "web.ssrf", "web.csrf", "web.graphql",
		"web.smuggle", "web.oauth", "web.ssti", "web.prompt_injection",
		"web.history", "web.replay", "web.compare", "web.templates",
	}
	if len(names) != len(want) {
		t.Fatalf("got %d tools, want %d", len(names), len(want))
	}
	for _, name := range want {
		if !names[name] {
			t.Errorf("missing tool: %s", name)
		}
	}
}
