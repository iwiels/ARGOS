package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripJSONC(t *testing.T) {
	src := `{
  // line comment
  "key": "value // not a comment",
  "other": "value /* not a comment */",
  /* block
     comment */
  "url": "https://example.com//path"
}`
	got := string(stripJSONC([]byte(src)))
	if !strings.Contains(got, `"key": "value // not a comment"`) {
		t.Errorf("string with // was mangled:\n%s", got)
	}
	if !strings.Contains(got, `"url": "https://example.com//path"`) {
		t.Errorf("url string was mangled:\n%s", got)
	}
	if strings.Contains(got, "line comment") {
		t.Errorf("line comment not removed:\n%s", got)
	}
	if strings.Contains(got, "block") {
		t.Errorf("block comment not removed:\n%s", got)
	}
}

func TestLoadWebToolsConfig_DefaultsWithoutConfig(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	specs := loadWebToolsConfig()
	if len(specs) != len(binSpecs) {
		t.Fatalf("got %d specs, want %d", len(specs), len(binSpecs))
	}
	for i := range specs {
		if specs[i].Version != binSpecs[i].Version || specs[i].Repo != binSpecs[i].Repo {
			t.Errorf("spec %s changed without config: %+v", specs[i].Name, specs[i])
		}
	}
}

func TestLoadWebToolsConfig_FileOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := `{
  // comment kept
  "webTools": {
    "nuclei": { "version": "v9.9.9" },
    "unknown-tool": { "version": "v1.0.0" },
    "dalfox": { "repo": "acme/dalfox", "archive": "zip" }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "argos.jsonc"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", dir)

	specs := loadWebToolsConfig()
	byName := map[string]BinarySpec{}
	for _, s := range specs {
		byName[s.Name] = s
	}
	if got := byName["nuclei"].Version; got != "v9.9.9" {
		t.Errorf("nuclei version = %q, want v9.9.9 (overridden)", got)
	}
	if got := byName["nuclei"].Repo; got != "projectdiscovery/nuclei" {
		t.Errorf("nuclei repo = %q, want inherited default", got)
	}
	if got := byName["dalfox"].Repo; got != "acme/dalfox" {
		t.Errorf("dalfox repo = %q, want acme/dalfox", got)
	}
	if got := byName["dalfox"].Archive; got != "zip" {
		t.Errorf("dalfox archive = %q, want zip", got)
	}
	if got := byName["httpx"].Version; got != "v1.10.0" {
		t.Errorf("httpx version = %q, want untouched default", got)
	}
}

func TestLoadWebToolsConfig_EnvOverrideWins(t *testing.T) {
	dir := t.TempDir()
	cfg := `{ "webTools": { "nuclei": { "version": "v1.1.1" } } }`
	os.WriteFile(filepath.Join(dir, "argos.jsonc"), []byte(cfg), 0o644)
	t.Setenv("OPENCODE_CONFIG_DIR", dir)
	t.Setenv("ARGOS_WEB_TOOLS_CONFIG", `{"nuclei":{"version":"v2.2.2"}}`)

	specs := loadWebToolsConfig()
	for _, s := range specs {
		if s.Name == "nuclei" {
			if s.Version != "v2.2.2" {
				t.Errorf("env override lost: nuclei version = %q, want v2.2.2", s.Version)
			}
		}
	}
}

func defaultVersion(name string) string {
	for _, s := range binSpecs {
		if s.Name == name {
			return s.Version
		}
	}
	return ""
}

func TestLoadWebToolsConfig_NaabuVersionOverrideRemovesDefaultArchitectureLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "argos.jsonc"), []byte(`{"webTools":{"naabu":{"version":"v2.3.5"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", dir)
	t.Setenv("ARGOS_WEB_TOOLS_CONFIG", "")

	for _, spec := range loadWebToolsConfig() {
		if spec.Name != "naabu" {
			continue
		}
		if spec.Version != "v2.3.5" {
			t.Fatalf("Naabu version = %q, want overridden v2.3.5", spec.Version)
		}
		if len(spec.UnsupportedTargets) != 0 {
			t.Fatalf("Naabu v2.3.5 inherited unsupported targets %v from v2.3.1", spec.UnsupportedTargets)
		}
		return
	}
	t.Fatal("Naabu spec is missing")
}
func TestEnvSpec_ReturnsEffectiveSpec(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "argos.jsonc"),
		[]byte(`{"webTools":{"gau":{"version":"v0.0.1"}}}`), 0o644)
	t.Setenv("OPENCODE_CONFIG_DIR", dir)

	env := NewEnv(t.TempDir())
	if got := env.Spec("gau").Version; got != "v0.0.1" {
		t.Errorf("env.Spec(gau).Version = %q, want v0.0.1", got)
	}
	if got := env.Spec("nuclei").Version; got != defaultVersion("nuclei") {
		t.Errorf("env.Spec(nuclei).Version = %q, want default %q", got, defaultVersion("nuclei"))
	}
	if env.Spec("does-not-exist") != nil {
		t.Error("unknown tool should return nil")
	}
}

func TestLoadNucleiScanConfig_Defaults(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	cfg := loadNucleiScanConfig()
	if cfg.RateLimit != defaultNucleiRateLimit {
		t.Errorf("rate limit = %d, want %d", cfg.RateLimit, defaultNucleiRateLimit)
	}
	if cfg.Concurrency != defaultNucleiConcurrency {
		t.Errorf("concurrency = %d, want %d", cfg.Concurrency, defaultNucleiConcurrency)
	}
}

func TestLoadNucleiScanConfig_FileOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := `{
  // nuclei tuning
  "webTools": {
    "nuclei": { "templatesVersion": "v10.5.0", "rateLimit": 42, "concurrency": 7 }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "argos.jsonc"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", dir)

	got := loadNucleiScanConfig()
	if got.RateLimit != 42 {
		t.Errorf("rate limit = %d, want 42", got.RateLimit)
	}
	if got.Concurrency != 7 {
		t.Errorf("concurrency = %d, want 7", got.Concurrency)
	}
}

func TestLoadWebToolsConfig_TemplatesVersionOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := `{ "webTools": { "nuclei": { "templatesVersion": "v10.5.0" } } }`
	if err := os.WriteFile(filepath.Join(dir, "argos.jsonc"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", dir)

	var tmpl *BinarySpec
	for i, s := range loadWebToolsConfig() {
		if s.Name == "nuclei-templates" {
			tmpl = &loadWebToolsConfig()[i]
			break
		}
	}
	if tmpl == nil {
		t.Fatal("nuclei-templates spec is missing")
	}
	if tmpl.Version != "v10.5.0" {
		t.Errorf("templates version = %q, want v10.5.0", tmpl.Version)
	}
	if tmpl.Kind != "templates" {
		t.Errorf("templates kind = %q, want templates", tmpl.Kind)
	}
	// an unknown version must not inherit the pin of another version
	if tmpl.SHA256 != "" {
		t.Errorf("sha256 pin = %q, want empty for an unpinned version", tmpl.SHA256)
	}
}

func TestLoadWebToolsConfig_TemplatesPinFollowsVersion(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	for _, s := range loadWebToolsConfig() {
		if s.Name != "nuclei-templates" {
			continue
		}
		if s.SHA256 != nucleiTemplatesSHA256[s.Version] {
			t.Errorf("sha256 pin = %q, want %q", s.SHA256, nucleiTemplatesSHA256[s.Version])
		}
		if s.SHA256 == "" {
			t.Error("the pinned templates version must carry a sha256 pin")
		}
		return
	}
	t.Fatal("nuclei-templates spec is missing")
}
