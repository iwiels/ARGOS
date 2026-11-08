package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEmbeddedRegistryParses(t *testing.T) {
	var file registryFile
	if err := json.Unmarshal(embeddedRegistry, &file); err != nil {
		t.Fatalf("embedded registry does not parse: %v", err)
	}
	if file.Version == "" {
		t.Error("embedded registry has no version")
	}
	if len(file.Rules) == 0 {
		t.Error("embedded registry has no rules")
	}
	if len(file.Vocabulary) == 0 {
		t.Error("embedded registry has no vocabulary")
	}
	if err := Err(); err != nil {
		t.Fatalf("embedded registry failed to load: %v", err)
	}
}

func TestLookup(t *testing.T) {
	rule, ok := Lookup("nuclei:generic-env")
	if !ok {
		t.Fatal("nuclei:generic-env not found in the registry")
	}
	if len(rule.CWE) == 0 {
		t.Error("nuclei:generic-env has no cwe")
	}
	if len(rule.OWASP) == 0 {
		t.Error("nuclei:generic-env has no owasp category")
	}
	if rule.SeverityFloor == "" {
		t.Error("nuclei:generic-env has no severity floor")
	}
	if len(rule.Tags) == 0 {
		t.Error("nuclei:generic-env has no tags")
	}
}

func TestLookupNotFound(t *testing.T) {
	if _, ok := Lookup("nuclei:does-not-exist"); ok {
		t.Error("an unknown rule must not be found")
	}
	if _, ok := Lookup(""); ok {
		t.Error("an empty rule id must not be found")
	}
	if _, ok := Lookup("not-a-scanner:rule"); ok {
		t.Error("a rule id without a scanner prefix must not be found")
	}
}

func TestAllReturnsEveryRule(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() returned no rules")
	}
	seen := map[string]bool{}
	for _, rule := range all {
		if rule.ID == "" {
			t.Error("a rule has no id")
		}
		if seen[rule.ID] {
			t.Errorf("duplicated rule id: %s", rule.ID)
		}
		seen[rule.ID] = true
	}
	if len(seen) != len(all) {
		t.Errorf("All() returned %d rules but %d unique ids", len(all), len(seen))
	}
	if len(all) < 150 || len(all) > 300 {
		t.Errorf("registry holds %d rules, expected between 150 and 300", len(all))
	}
}

func TestVocabulary(t *testing.T) {
	vocabulary := Vocabulary()
	if len(vocabulary) == 0 {
		t.Fatal("the vocabulary is empty")
	}
	for _, tag := range []string{"sqli", "xss", "tls", "information-disclosure", "default-credentials"} {
		if !IsCanonicalTag(tag) {
			t.Errorf("%q must belong to the canonical vocabulary", tag)
		}
	}
	if IsCanonicalTag("not-a-real-tag") {
		t.Error("a tag outside the vocabulary must be rejected")
	}
}

func TestCWEForTag(t *testing.T) {
	cases := map[string]string{
		"sqli":                   "CWE-89",
		"xss":                    "CWE-79",
		"path-traversal":         "CWE-22",
		"ssrf":                   "CWE-918",
		"command-injection":      "CWE-78",
		"information-disclosure": "CWE-200",
	}
	for tag, want := range cases {
		if got := CWEForTag(tag); got != want {
			t.Errorf("CWEForTag(%q) = %q, want %q", tag, got, want)
		}
	}
	if got := CWEForTag("not-a-real-tag"); got != "" {
		t.Errorf("an unknown tag must not produce a cwe, got %q", got)
	}
}

// The Go mirror is generated from the TypeScript source. The test reads the
// source from the repository to prove the two did not drift.
func TestMirrorIsInSyncWithTheSource(t *testing.T) {
	source := filepath.Join("..", "..", "..", "..", "..", "packages", "core", "src", "security", "rules", "registry.json")
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("cannot read the registry source: %v", err)
	}

	var sourceFile struct {
		Version    string            `json:"version"`
		Vocabulary []string          `json:"vocabulary"`
		CWEByTag   map[string]string `json:"cwe_by_tag"`
		Rules      []Rule            `json:"rules"`
	}
	if err := json.Unmarshal(raw, &sourceFile); err != nil {
		t.Fatalf("the registry source does not parse: %v", err)
	}

	if sourceFile.Version != Version() {
		t.Errorf("version drift: source %q, mirror %q", sourceFile.Version, Version())
	}
	if !reflect.DeepEqual(sortedCopy(sourceFile.Vocabulary), sortedCopy(Vocabulary())) {
		t.Error("the vocabulary drifted between the source and the mirror")
	}
	if !reflect.DeepEqual(sourceFile.CWEByTag, map[string]string(CWEByTagAll())) {
		t.Error("cwe_by_tag drifted between the source and the mirror")
	}
	if len(sourceFile.Rules) != len(All()) {
		t.Fatalf("rule count drift: source %d, mirror %d", len(sourceFile.Rules), len(All()))
	}
	for _, rule := range sourceFile.Rules {
		mirrored, ok := Lookup(rule.ID)
		if !ok {
			t.Errorf("the mirror is missing the rule %s", rule.ID)
			continue
		}
		if !reflect.DeepEqual(rule.CWE, mirrored.CWE) ||
			!reflect.DeepEqual(rule.OWASP, mirrored.OWASP) ||
			rule.SeverityFloor != mirrored.SeverityFloor ||
			!reflect.DeepEqual(rule.Tags, mirrored.Tags) ||
			!reflect.DeepEqual(rule.References, mirrored.References) {
			t.Errorf("the rule %s drifted between the source and the mirror", rule.ID)
		}
	}
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
