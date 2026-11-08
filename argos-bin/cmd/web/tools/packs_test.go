package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeRegistry(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "registry.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing registry: %v", err)
	}
}

func TestLoadPacks_ValidatesRegistry(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		dir := t.TempDir()
		writeRegistry(t, dir, `{"version":1,"packs":[{"name":"x","path":"x"}]}`)
		if _, err := LoadPacks(dir); err == nil {
			t.Fatal("a pack without id must be rejected")
		}
	})

	t.Run("duplicate id", func(t *testing.T) {
		dir := t.TempDir()
		writeRegistry(t, dir, `{"version":1,"packs":[{"id":"a"},{"id":"a"}]}`)
		if _, err := LoadPacks(dir); err == nil {
			t.Fatal("a duplicated pack id must be rejected")
		}
	})

	t.Run("path traversal", func(t *testing.T) {
		dir := t.TempDir()
		writeRegistry(t, dir, `{"version":1,"packs":[{"id":"a","path":"../outside"}]}`)
		if _, err := LoadPacks(dir); err == nil {
			t.Fatal("a pack path outside the packs directory must be rejected")
		}
	})

	t.Run("path defaults to the id", func(t *testing.T) {
		dir := t.TempDir()
		writeRegistry(t, dir, `{"version":1,"packs":[{"id":"idor","enabled":true}]}`)
		registry, err := LoadPacks(dir)
		if err != nil {
			t.Fatalf("LoadPacks: %v", err)
		}
		if registry.Packs[0].Path != "idor" {
			t.Errorf("path = %q, want the id", registry.Packs[0].Path)
		}
	})

	t.Run("missing registry", func(t *testing.T) {
		if _, err := LoadPacks(t.TempDir()); err == nil {
			t.Fatal("a missing registry must be reported, not ignored")
		}
	})
}

func TestSelectPacks(t *testing.T) {
	registry := PackRegistry{
		Version: 1,
		Packs: []Pack{
			{ID: "idor", Enabled: true},
			{ID: "cicd", Enabled: false},
		},
	}

	t.Run("empty request runs the enabled packs", func(t *testing.T) {
		packs, err := SelectPacks(registry, nil)
		if err != nil {
			t.Fatalf("SelectPacks: %v", err)
		}
		if len(packs) != 1 || packs[0].ID != "idor" {
			t.Errorf("packs = %v, want [idor]", packs)
		}
	})

	t.Run("explicit request wins over the enabled flag", func(t *testing.T) {
		packs, err := SelectPacks(registry, []string{"cicd"})
		if err != nil {
			t.Fatalf("SelectPacks: %v", err)
		}
		if len(packs) != 1 || packs[0].ID != "cicd" {
			t.Errorf("packs = %v, want [cicd]", packs)
		}
	})

	t.Run("unknown pack lists the known ones", func(t *testing.T) {
		_, err := SelectPacks(registry, []string{"nope"})
		if err == nil {
			t.Fatal("an unknown pack must be an error")
		}
		for _, want := range []string{"nope", "cicd", "idor"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})

	t.Run("repeated request yields one pack", func(t *testing.T) {
		packs, err := SelectPacks(registry, []string{"idor", "IDOR", "idor"})
		if err != nil {
			t.Fatalf("SelectPacks: %v", err)
		}
		if len(packs) != 1 {
			t.Errorf("packs = %v, want one idor", packs)
		}
	})
}

func TestPackDirs_ReportsMissing(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "idor"), 0o755); err != nil {
		t.Fatal(err)
	}
	dirs, missing := PackDirs(base, []Pack{{ID: "idor", Path: "idor"}, {ID: "cicd", Path: "cicd"}})
	if len(dirs) != 1 || dirs[0] != filepath.Join(base, "idor") {
		t.Errorf("dirs = %v, want the idor dir", dirs)
	}
	if len(missing) != 1 || missing[0] != "cicd" {
		t.Errorf("missing = %v, want [cicd]", missing)
	}
}

func TestPacksFingerprint_StableAndContentSensitive(t *testing.T) {
	base := t.TempDir()
	pack := filepath.Join(base, "idor")
	if err := os.MkdirAll(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(pack, "a.yaml")
	if err := os.WriteFile(file, []byte("id: argos-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	first := PacksFingerprint(base, []string{pack})
	second := PacksFingerprint(base, []string{pack})
	if first != second {
		t.Errorf("fingerprint is not stable: %s != %s", first, second)
	}
	if len(first) != 64 {
		t.Errorf("fingerprint = %q, want a sha256 hex digest", first)
	}

	if err := os.WriteFile(file, []byte("id: argos-a\nseverity: high\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed := PacksFingerprint(base, []string{pack}); changed == first {
		t.Error("changing a template must change the fingerprint")
	}
}

// bundledPacksDir locates argos-config/templates/nuclei from the test file, so
// the contract of the shipped packs is enforced by CI and not only reviewed by
// hand.
func bundledPacksDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "argos-config", "templates", "nuclei"))
	if !isDir(dir) {
		t.Skipf("bundled packs not found at %s", dir)
	}
	return dir
}

// TestArgosConfigDeclaresKnownPacks keeps the shipped config and the registry
// in sync: a pack renamed in one place must not silently stop running because
// the other still lists the old id.
func TestArgosConfigDeclaresKnownPacks(t *testing.T) {
	base := bundledPacksDir(t)
	registry, err := LoadPacks(base)
	if err != nil {
		t.Fatalf("LoadPacks: %v", err)
	}

	configPath := filepath.Clean(filepath.Join(base, "..", "..", "argos.jsonc"))
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Skipf("argos.jsonc not found at %s", configPath)
	}

	var doc struct {
		WebTools map[string]struct {
			Packs []string `json:"packs"`
		} `json:"webTools"`
	}
	if err := json.Unmarshal(stripJSONC(raw), &doc); err != nil {
		t.Fatalf("parsing %s: %v", configPath, err)
	}

	declared := doc.WebTools["nuclei"].Packs
	if len(declared) == 0 {
		t.Fatal("argos.jsonc does not declare webTools.nuclei.packs")
	}

	known := map[string]bool{}
	for _, pack := range registry.Packs {
		known[pack.ID] = true
	}
	for _, id := range declared {
		if !known[id] {
			t.Errorf("argos.jsonc declares unknown pack %q", id)
		}
	}
}

func TestBundledPacksAreValid(t *testing.T) {
	base := bundledPacksDir(t)
	registry, err := LoadPacks(base)
	if err != nil {
		t.Fatalf("LoadPacks: %v", err)
	}
	if len(registry.Packs) == 0 {
		t.Fatal("the registry has no packs")
	}

	seen := map[string]string{}
	templates := 0
	for _, pack := range registry.Packs {
		dirs, missing := PackDirs(base, []Pack{pack})
		if len(missing) > 0 {
			t.Errorf("pack %q is declared but its directory is missing", pack.ID)
			continue
		}
		summaries := PackTemplates(dirs[0])
		if len(summaries) == 0 {
			t.Errorf("pack %q has no templates", pack.ID)
			continue
		}
		for _, summary := range summaries {
			templates++
			if previous, ok := seen[summary.ID]; ok {
				t.Errorf("duplicate template id %q in %s and %s", summary.ID, previous, summary.File)
			}
			seen[summary.ID] = summary.File
			if !strings.HasPrefix(summary.ID, "argos-") {
				t.Errorf("%s: id %q must start with argos-", summary.File, summary.ID)
			}
			if summary.Name == "" || summary.Severity == "" {
				t.Errorf("%s: the catalog needs a name and a severity", summary.File)
			}
			validateBundledTemplate(t, dirs[0], summary, pack.ID)
		}
	}
	if templates == 0 {
		t.Fatal("no templates found")
	}
}

func validateBundledTemplate(t *testing.T, dir string, summary TemplateSummary, packID string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, summary.File))
	if err != nil {
		t.Errorf("%s: %v", summary.File, err)
		return
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if strings.Contains(body, "\t") {
		t.Errorf("%s: tabs are not valid YAML indentation", summary.File)
	}
	if !strings.Contains(body, "cvss-metrics: CVSS:3.1/") {
		t.Errorf("%s: missing a CVSS v3.1 vector", summary.File)
	}
	if !strings.Contains(body, "cwe-id: CWE-") {
		t.Errorf("%s: missing the CWE classification", summary.File)
	}
	if !strings.Contains(body, "    argos-pack: "+packID) {
		t.Errorf("%s: argos-pack must match the pack directory", summary.File)
	}
	for _, key := range []string{"argos-evidence:", "argos-requires-auth:", "argos-severity-floor:", "max-request:"} {
		if !strings.Contains(body, key) {
			t.Errorf("%s: missing %s", summary.File, key)
		}
	}
	if !strings.Contains(body, "\nhttp:\n") {
		t.Errorf("%s: missing the http block", summary.File)
	}
	if !strings.Contains(body, "matchers:") {
		t.Errorf("%s: a template without matchers can never be a finding", summary.File)
	}
	for _, token := range []string{`(?=`, `(?!`, `(?<=`, `(?<!`} {
		if strings.Contains(body, token) {
			t.Errorf("%s: RE2 does not support lookaround (%s)", summary.File, token)
		}
	}

	// A template that probes several paths reports the same issue once.
	paths := strings.Count(body, `- "{{BaseURL}}`)
	if paths > 1 && !strings.Contains(body, "stop-at-first-match: true") {
		t.Errorf("%s: %d paths need stop-at-first-match", summary.File, paths)
	}
}
