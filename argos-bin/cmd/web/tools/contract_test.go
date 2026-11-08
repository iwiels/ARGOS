package tools

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestFindingJSONRoundTrip(t *testing.T) {
	original := Finding{
		ID:          "finding_1",
		Source:      "web.scan",
		SourceTool:  "web.sqli",
		RuleID:      "nuclei:exposed-env-file",
		Title:       "Exposed environment file",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceProbable,
		CWE:         "CWE-200",
		OWASP:       []string{"A05:2021"},
		Target:      "https://example.com/.env",
		Vector:      "id",
		Evidence:    map[string]any{"template": "exposed-env-file", "marker": true},
		Remediation: "Remove the file from the repository",
		CVSS:        &CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
		Tags:        []string{"secret-exposure", ".env"},
		References:  []string{"https://example.com/advisory"},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded Finding
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", decoded, original)
	}
}

func TestFindingJSONKeys(t *testing.T) {
	encoded, err := json.Marshal(Finding{
		Source:   "web.scan",
		Title:    "t",
		Severity: SeverityInfo,
		Target:   "https://example.com",
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	want := map[string]any{
		"source":   "web.scan",
		"title":    "t",
		"severity": "info",
		"target":   "https://example.com",
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("optional fields must be omitted:\n got %v\nwant %v", decoded, want)
	}
}

func TestFindingToMapMatchesJSON(t *testing.T) {
	finding := Finding{
		ID:         "finding_1",
		Source:     "web.sqli",
		SourceTool: "web.sqli",
		RuleID:     "sqlmap",
		Title:      "SQL Injection Confirmada (sqlmap)",
		Severity:   SeverityCritical,
		Confidence: ConfidenceConfirmed,
		CWE:        "CWE-89",
		OWASP:      []string{"A03:2021"},
		Target:     "https://example.com/item?id=1",
		Vector:     "id",
		Evidence:   map[string]any{"parameter": "id"},
		CVSS:       &CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
		Tags:       []string{"sqli"},
		References: []string{"https://example.com/advisory"},
	}

	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var fromStruct map[string]any
	if err := json.Unmarshal(encoded, &fromStruct); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	encodedMap, err := json.Marshal(finding.ToMap())
	if err != nil {
		t.Fatalf("marshal of the map failed: %v", err)
	}
	var fromMap map[string]any
	if err := json.Unmarshal(encodedMap, &fromMap); err != nil {
		t.Fatalf("unmarshal of the map failed: %v", err)
	}
	if !reflect.DeepEqual(fromMap, fromStruct) {
		t.Fatalf("ToMap drifted from the JSON shape:\n got %v\nwant %v", fromMap, fromStruct)
	}

	wantKeys := []string{
		"confidence", "cvss", "cwe", "evidence", "id", "owasp", "references",
		"rule_id", "severity", "source", "source_tool", "tags", "target", "title", "vector",
	}
	gotKeys := make([]string, 0, len(finding.ToMap()))
	for key := range finding.ToMap() {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("unexpected keys:\n got %v\nwant %v", gotKeys, wantKeys)
	}
}

func TestNormalizeSeverityContract(t *testing.T) {
	cases := map[string]string{
		"critical":    "critical",
		"CRIT":        "critical",
		"crítico":     "critical",
		"critico":     "critical",
		"high":        "high",
		"ALTO":        "high",
		"medium":      "medium",
		"medio":       "medium",
		"media":       "medium",
		"moderate":    "medium",
		"low":         "low",
		"bajo":        "low",
		"informativo": "info",
		"unknown":     "info",
		"":            "info",
		"WARN":        "info",
		"not a level": "info",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeConfidenceContract(t *testing.T) {
	cases := map[string]string{
		"confirmed": "confirmed",
		"CONFIRMED": "confirmed",
		"probable":  "probable",
		"possible":  "possible",
		"":          "possible",
		"maybe":     "possible",
	}
	for in, want := range cases {
		if got := normalizeConfidence(in); got != want {
			t.Errorf("normalizeConfidence(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	cases := map[string]string{
		"CWE-89": "CWE-89",
		"cwe-89": "CWE-89",
		"CWE 89": "CWE-89",
		"89":     "CWE-89",
		" 200 ":  "CWE-200",
		"":       "",
		"nope":   "",
		"CWE-":   "",
	}
	for in, want := range cases {
		if got := normalizeCWE(in); got != want {
			t.Errorf("normalizeCWE(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseCvssVectorString(t *testing.T) {
	vector := parseCvssVectorString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if vector == nil {
		t.Fatal("expected a base vector")
	}
	want := CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"}
	if *vector != want {
		t.Fatalf("got %+v, want %+v", *vector, want)
	}
	if parseCvssVectorString("CVSS:3.1/AV:N/AC:L") != nil {
		t.Error("a partial vector must not produce a score")
	}
	if parseCvssVectorString("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") != nil {
		t.Error("an invalid metric must be rejected")
	}
	if parseCvssVectorString("not a vector") != nil {
		t.Error("a non-vector string must be rejected")
	}
}

func TestDedupeTags(t *testing.T) {
	got := dedupeTags([]string{" SQLi ", "sqli", "", "TLS"})
	want := []string{"sqli", "tls"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if dedupeTags([]string{"  "}) != nil {
		t.Error("an empty tag list must stay nil")
	}
}

// A nuclei template must reach the backend with the fields the compliance and
// ATT&CK engines match on: source_tool, tags, cwe and vector.
func TestParseNucleiFillsTheContract(t *testing.T) {
	out := `{"template-id":"exposed-env-file","info":{"name":"Exposed environment file","severity":"high","tags":["exposure","files"],"reference":"https://example.com/advisory","remediation":"Remove the file from the web root","classification":{"cwe-id":"CWE-200","owasp":"A05:2021","cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},"type":"http","matched-at":"https://example.com/.env"}`
	fs := parseNuclei(out, "https://example.com", "web.scan")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.SourceTool != "web.scan" || f.Source != "web.scan" {
		t.Errorf("source/source_tool = %q/%q", f.Source, f.SourceTool)
	}
	if f.RuleID != "nuclei:exposed-env-file" {
		t.Errorf("rule_id = %q", f.RuleID)
	}
	if f.CWE != "CWE-200" {
		t.Errorf("cwe = %q", f.CWE)
	}
	if len(f.OWASP) != 1 || f.OWASP[0] != "A05:2021" {
		t.Errorf("owasp = %v", f.OWASP)
	}
	if f.Vector != "https://example.com/.env" {
		t.Errorf("vector = %q", f.Vector)
	}
	if f.Target != "https://example.com" {
		t.Errorf("target = %q", f.Target)
	}
	if f.Remediation != "Remove the file from the web root" {
		t.Errorf("remediation = %q", f.Remediation)
	}
	if len(f.References) != 1 || f.References[0] != "https://example.com/advisory" {
		t.Errorf("references = %v", f.References)
	}
	if f.CVSS == nil || f.CVSS.AV != "N" || f.CVSS.C != "H" {
		t.Errorf("cvss = %+v", f.CVSS)
	}
	// The template tags are filtered against the canonical vocabulary the
	// compliance and ATT&CK engines match on; the taxonomy of the rule comes
	// from the registry.
	if !reflect.DeepEqual(f.Tags, []string{"secret-exposure", ".env", "information-disclosure"}) {
		t.Errorf("tags = %v", f.Tags)
	}
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q", f.Confidence)
	}
}
