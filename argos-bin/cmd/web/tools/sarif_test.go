package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A SARIF document with the parts the previous parser dropped: the taint
// chain of the result, the taxonomies, the suppressions, the numeric severity
// score and more than one location.
const richSarif = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "rules": [
            {
              "id": "python.lang.security.audit.eval-detected",
              "helpUri": "https://semgrep.dev/r/python.lang.security.audit.eval-detected",
              "defaultConfiguration": { "level": "error" },
              "properties": {
                "precision": "very-high",
                "tags": ["CWE-95", "OWASP-A03:2021", "security"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.lang.security.audit.eval-detected",
          "level": "error",
          "message": { "text": "Detected the use of eval()" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/handler.py" },
                "region": { "startLine": 42, "endLine": 42, "snippet": { "text": "eval(payload)" } }
              }
            },
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/routes.py" },
                "region": { "startLine": 7, "endLine": 9 }
              }
            }
          ],
          "codeFlows": [
            {
              "message": { "text": "Untrusted dataflow from app/handler.py:42 to app/handler.py:42" },
              "threadFlows": [
                {
                  "locations": [
                    {
                      "location": {
                        "message": { "text": "Source: 'request.args'" },
                        "physicalLocation": {
                          "artifactLocation": { "uri": "app/handler.py" },
                          "region": { "startLine": 42, "endLine": 42, "snippet": { "text": "request.args" } }
                        }
                      },
                      "nestingLevel": 0
                    },
                    {
                      "location": {
                        "message": { "text": "Sink: 'eval(payload)'" },
                        "physicalLocation": {
                          "artifactLocation": { "uri": "app/handler.py" },
                          "region": { "startLine": 42, "endLine": 42 }
                        }
                      },
                      "nestingLevel": 1
                    }
                  ]
                }
              ]
            }
          ],
          "partialFingerprints": { "matchBasedId/v1": "abc123" },
          "taxonomies": [
            { "id": "CWE-95", "name": "CWE-95", "toolComponent": { "name": "CWE" } }
          ],
          "fixes": [
            {
              "description": { "text": "Replace eval() with ast.literal_eval()" },
              "artifactChanges": [
                {
                  "artifactLocation": { "uri": "app/handler.py" },
                  "replacements": [
                    {
                      "deletedRegion": { "startLine": 42 },
                      "insertedContent": { "text": "ast.literal_eval(payload)" }
                    }
                  ]
                }
              ]
            }
          ],
          "properties": { "security-severity": "9.1" }
        }
      ]
    }
  ]
}`

func TestParseSarifKeepsTheRichSignal(t *testing.T) {
	findings, err := parseSarifReport([]byte(richSarif), "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.CWE != "CWE-95" {
		t.Errorf("cwe = %q, want CWE-95", f.CWE)
	}
	if len(f.OWASP) != 1 || f.OWASP[0] != "A03:2021" {
		t.Errorf("owasp = %v, want [A03:2021]", f.OWASP)
	}
	// The numeric score is authoritative: 9.1 is critical, not the "high" the
	// level alone would have produced.
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityCritical)
	}
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q", f.Confidence, ConfidenceConfirmed)
	}
	if f.Target != "app/handler.py" {
		t.Errorf("target = %q", f.Target)
	}
	if f.Vector != "app/handler.py:42" {
		t.Errorf("vector = %q", f.Vector)
	}
	if f.Title != "Detected the use of eval()" {
		t.Errorf("title = %q", f.Title)
	}
	if f.RuleID != "semgrep:python.lang.security.audit.eval-detected" {
		t.Errorf("rule_id = %q", f.RuleID)
	}
	if len(f.References) == 0 || !strings.Contains(f.References[0], "semgrep.dev") {
		t.Errorf("references = %v", f.References)
	}
	if !strings.Contains(f.Remediation, "ast.literal_eval") {
		t.Errorf("remediation = %q", f.Remediation)
	}

	locations, ok := f.Evidence["locations"].([]map[string]any)
	if !ok {
		t.Fatalf("evidence.locations = %T, want []map[string]any", f.Evidence["locations"])
	}
	if len(locations) != 2 {
		t.Fatalf("expected 2 locations, got %d", len(locations))
	}
	if locations[0]["file"] != "app/handler.py" || locations[0]["line"] != 42 {
		t.Errorf("first location = %v", locations[0])
	}
	if locations[1]["file"] != "app/routes.py" || locations[1]["line"] != 7 {
		t.Errorf("second location = %v", locations[1])
	}
	if locations[0]["snippet"] != "eval(payload)" {
		t.Errorf("snippet = %v", locations[0]["snippet"])
	}

	dataflow, ok := f.Evidence["dataflow"].([]map[string]any)
	if !ok {
		t.Fatalf("evidence.dataflow = %T, want []map[string]any", f.Evidence["dataflow"])
	}
	if len(dataflow) != 2 {
		t.Fatalf("expected 2 dataflow steps, got %d", len(dataflow))
	}
	if dataflow[0]["message"] != "Source: 'request.args'" {
		t.Errorf("dataflow source = %v", dataflow[0]["message"])
	}
	if dataflow[1]["message"] != "Sink: 'eval(payload)'" {
		t.Errorf("dataflow sink = %v", dataflow[1]["message"])
	}

	fingerprints, ok := f.Evidence["partialFingerprints"].(map[string]string)
	if !ok {
		t.Fatalf("evidence.partialFingerprints = %T, want map[string]string", f.Evidence["partialFingerprints"])
	}
	if fingerprints["matchBasedId/v1"] != "abc123" {
		t.Errorf("partialFingerprints = %v", fingerprints)
	}
}

func TestParseSarifDropsSuppressedResults(t *testing.T) {
	doc := `{
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": { "name": "semgrep" } },
        "results": [
          {
            "ruleId": "nosemgrep.rule",
            "level": "warning",
            "message": { "text": "already reviewed" },
            "suppressions": [{ "kind": "inSource", "justification": "false positive" }]
          },
          {
            "ruleId": "external.rule",
            "level": "warning",
            "message": { "text": "suppressed elsewhere" },
            "suppressions": [{ "kind": "external" }]
          },
          {
            "ruleId": "reported.rule",
            "level": "warning",
            "message": { "text": "still reported" }
          }
        ]
      }]
    }`

	findings, err := parseSarifReport([]byte(doc), "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the suppressed results to be dropped, got %d findings", len(findings))
	}
	if findings[0].RuleID != "semgrep:reported.rule" {
		t.Errorf("rule_id = %q", findings[0].RuleID)
	}
}

// Semgrep does not repeat the level on every result: it lives in the rule
// descriptor. Without that fallback every semgrep finding would degrade to
// "info".
func TestParseSarifFallsBackToTheRuleLevel(t *testing.T) {
	doc := `{
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "Semgrep OSS",
            "rules": [
              { "id": "rules.classic", "defaultConfiguration": { "level": "warning" }, "properties": { "precision": "very-high" } }
            ]
          }
        },
        "results": [
          { "ruleId": "rules.classic", "message": { "text": "tainted flow" } }
        ]
      }]
    }`

	findings, err := parseSarifReport([]byte(doc), "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityMedium)
	}
	// Without a numeric score the level is only a floor: the finding stays
	// "possible".
	if findings[0].Confidence != ConfidencePossible {
		t.Errorf("confidence = %q, want %q", findings[0].Confidence, ConfidencePossible)
	}
}

// A result without level and without score carries no severity signal at all.
func TestParseSarifWithoutLevelAndScore(t *testing.T) {
	doc := `{
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": { "name": "unknown" } },
        "results": [ { "ruleId": "bare.rule", "message": { "text": "no signal" } } ]
      }]
    }`

	findings, err := parseSarifReport([]byte(doc), "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityInfo {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityInfo)
	}
	if findings[0].Confidence != ConfidencePossible {
		t.Errorf("confidence = %q, want %q", findings[0].Confidence, ConfidencePossible)
	}
}

func TestParseSarifSecuritySeverityBands(t *testing.T) {
	cases := map[string]string{
		"9.8": SeverityCritical,
		"9.0": SeverityCritical,
		"8.9": SeverityHigh,
		"7.0": SeverityHigh,
		"6.9": SeverityMedium,
		"4.0": SeverityMedium,
		"3.9": SeverityLow,
		"0.1": SeverityLow,
		"0.0": SeverityInfo,
		// An unreadable score leaves only the level as a signal.
		"junk": SeverityMedium,
	}

	for score, want := range cases {
		doc := `{
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": { "name": "trivy" } },
            "results": [
              { "ruleId": "CVE-2024-0001", "level": "warning", "message": { "text": "vuln" },
                "properties": { "security-severity": "` + score + `", "precision": "very-high" } }
            ]
          }]
        }`
		findings, err := parseSarifReport([]byte(doc), "code.deps")
		if err != nil {
			t.Fatalf("parseSarifReport failed: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != want {
			t.Errorf("security-severity %q → %q, want %q", score, findings[0].Severity, want)
		}
	}
}

func TestParseSarifReadsEveryRun(t *testing.T) {
	doc := `{
      "version": "2.1.0",
      "runs": [
        { "tool": { "driver": { "name": "semgrep" } }, "results": [ { "ruleId": "a", "message": { "text": "a" } } ] },
        { "tool": { "driver": { "name": "trivy" } }, "results": [ { "ruleId": "b", "message": { "text": "b" } } ] }
      ]
    }`

	findings, err := parseSarifReport([]byte(doc), "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

// The core exports its findings as SARIF; the Go parser must read that
// document back without losing the CWE, the CVSS vector, the dataflow or the
// fingerprints.
func TestParseSarifReadsTheCoreExport(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "packages", "core", "test", "fixtures", "sarif-roundtrip.sarif.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("core export fixture not available: %v", err)
	}

	findings, err := parseSarifReport(data, "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.CWE != "CWE-89" {
		t.Errorf("cwe = %q, want CWE-89", f.CWE)
	}
	if f.CVSS == nil {
		t.Fatal("the cvss vector must survive the round trip")
	}
	want := CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"}
	if *f.CVSS != want {
		t.Errorf("cvss = %+v, want %+v", *f.CVSS, want)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityCritical)
	}

	dataflow, ok := f.Evidence["dataflow"].([]map[string]any)
	if !ok {
		t.Fatalf("evidence.dataflow = %T, want []map[string]any", f.Evidence["dataflow"])
	}
	if len(dataflow) != 2 {
		t.Fatalf("expected 2 dataflow steps, got %d", len(dataflow))
	}
	if dataflow[0]["message"] != "Source: request.args" {
		t.Errorf("dataflow source = %v", dataflow[0]["message"])
	}

	fingerprints, ok := f.Evidence["partialFingerprints"].(map[string]string)
	if !ok {
		t.Fatalf("evidence.partialFingerprints = %T, want map[string]string", f.Evidence["partialFingerprints"])
	}
	if fingerprints["argos/v1"] == "" {
		t.Errorf("the fingerprint of the finding must survive: %v", fingerprints)
	}
}

func TestParseSarifRejectsBrokenDocuments(t *testing.T) {
	if _, err := parseSarifReport([]byte("{not json"), "code.sast"); err == nil {
		t.Fatal("a broken document must be an error")
	}
}

func TestExtractCweAndOwasp(t *testing.T) {
	cases := map[string]string{
		"CWE-89":                          "CWE-89",
		"cwe-89":                          "CWE-89",
		"CWE-89: Improper Neutralization": "CWE-89",
		"external/cwe/cwe-078/cwe-078":    "CWE-078",
		"nothing here":                    "",
	}
	for input, want := range cases {
		if got := extractCwe(input); got != want {
			t.Errorf("extractCwe(%q) = %q, want %q", input, got, want)
		}
	}

	owaspCases := map[string]string{
		"OWASP-A03:2021": "A03:2021",
		"A03:2021":       "A03:2021",
		"owasp a01:2021": "A01:2021",
		"nothing":        "",
	}
	for input, want := range owaspCases {
		if got := extractOwasp(input); got != want {
			t.Errorf("extractOwasp(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSarifEvidenceSurvivesTheJSONRoundTrip(t *testing.T) {
	findings, err := parseSarifReport([]byte(richSarif), "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	encoded, err := json.Marshal(findings[0].ToMap())
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	evidence, ok := decoded["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("evidence = %T", decoded["evidence"])
	}
	if _, ok := evidence["dataflow"]; !ok {
		t.Error("the dataflow must reach the wire")
	}
	if !reflect.DeepEqual(evidence["partialFingerprints"], map[string]any{"matchBasedId/v1": "abc123"}) {
		t.Errorf("partialFingerprints = %v", evidence["partialFingerprints"])
	}
}
