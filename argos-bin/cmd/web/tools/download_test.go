package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/guard"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

func TestEnsureNaabuUsesConfiguredPinnedToolCache(t *testing.T) {
	toolsDir := t.TempDir()
	t.Setenv(toolsDirEnv, toolsDir)

	binaryName := (&BinarySpec{Bin: "naabu"}).TargetExecutableName()
	binaryPath := filepath.Join(toolsDir, "naabu", binaryName)
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("cached naabu"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, installed, err := EnsureNaabu(context.Background())
	if err != nil {
		t.Fatalf("EnsureNaabu() error = %v", err)
	}
	if got != binaryPath {
		t.Fatalf("EnsureNaabu() path = %q, want %q", got, binaryPath)
	}
	if installed {
		t.Fatal("EnsureNaabu() reports an already cached binary as newly installed")
	}
}

func TestPickArchiveAsset(t *testing.T) {
	assets := []string{
		"nuclei_3.11.0_checksums.txt",
		"nuclei_3.11.0_linux_amd64.zip",
		"nuclei_3.11.0_windows_amd64.zip",
		"nuclei_3.11.0_darwin_arm64.zip",
	}
	got := pickArchiveAsset(assets, "windows", "amd64", "zip")
	if got != "nuclei_3.11.0_windows_amd64.zip" {
		t.Errorf("windows amd64 = %q", got)
	}
	got = pickArchiveAsset(assets, "darwin", "arm64", "zip")
	if got != "nuclei_3.11.0_darwin_arm64.zip" {
		t.Errorf("darwin arm64 = %q", got)
	}
	got = pickArchiveAsset(assets, "freebsd", "amd64", "zip")
	if got != "" {
		t.Errorf("unsupported os should be empty, got %q", got)
	}
}

func TestPickArchiveAsset_TarGzFallback(t *testing.T) {
	assets := []string{"dalfox_3.2.0_checksums.txt", "dalfox_3.2.0_windows_amd64.tar.gz"}
	got := pickArchiveAsset(assets, "windows", "amd64", "tar.gz")
	if got != "dalfox_3.2.0_windows_amd64.tar.gz" {
		t.Errorf("dalfox asset = %q", got)
	}
}

// real-world dalfox release naming uses hyphens and x86_64, and windows ships
// as zip while linux/macos ship as tar.gz (the spec says tar.gz)
func TestPickArchiveAsset_DalfoxHyphenNaming(t *testing.T) {
	assets := []string{
		"checksum.txt",
		"dalfox-v3.2.0-linux-aarch64.tar.gz",
		"dalfox-v3.2.0-linux-x86_64-musl.tar.gz",
		"dalfox-v3.2.0-linux-x86_64.tar.gz",
		"dalfox-v3.2.0-macos-aarch64.tar.gz",
		"dalfox-v3.2.0-windows-x86_64.zip",
	}
	// windows is zip even though the spec declares tar.gz → extension fallback
	got := pickArchiveAsset(assets, "windows", "amd64", "tar.gz")
	if got != "dalfox-v3.2.0-windows-x86_64.zip" {
		t.Errorf("windows amd64 = %q, want dalfox-v3.2.0-windows-x86_64.zip", got)
	}
	got = pickArchiveAsset(assets, "darwin", "arm64", "tar.gz")
	if got != "dalfox-v3.2.0-macos-aarch64.tar.gz" {
		t.Errorf("macos arm64 = %q", got)
	}
	// must not pick the musl (static) variant for plain linux amd64
	got = pickArchiveAsset(assets, "linux", "amd64", "tar.gz")
	if got != "dalfox-v3.2.0-linux-x86_64.tar.gz" {
		t.Errorf("linux amd64 = %q", got)
	}
}

func TestPickChecksumAsset(t *testing.T) {
	if got := pickChecksumAsset([]string{"a.zip", "b-checksums.txt"}); got != "b-checksums.txt" {
		t.Errorf("got %q", got)
	}
	if got := pickChecksumAsset([]string{"a.zip", "katana-1.6.1-checksums.txt"}); got != "katana-1.6.1-checksums.txt" {
		t.Errorf("katana checksums = %q", got)
	}
	if got := pickChecksumAsset([]string{"a.zip"}); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestChecksumFor(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	content := hash + "  nuclei_3.11.0_windows_amd64.zip\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  nuclei_3.11.0_linux_amd64.zip\n"
	got := checksumFor("nuclei_3.11.0_windows_amd64.zip", content)
	if got != hash {
		t.Errorf("checksumFor = %q, want %q", got, hash)
	}
	// unknown format → empty (best-effort skip)
	if got := checksumFor("x.zip", "not a checksum file"); got != "" {
		t.Errorf("expected empty for unknown format, got %q", got)
	}
}

func TestDetectWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123")
		w.WriteHeader(403)
		w.Write([]byte("blocked"))
	}))
	defer srv.Close()

	detected, evidence, _ := guard.DetectWAFDetailed(srv.Client(), srv.URL)
	if len(detected) == 0 {
		t.Fatal("expected a WAF to be detected")
	}
	found := false
	for _, d := range detected {
		if d == "Cloudflare" {
			found = true
		}
	}
	if !found {
		t.Errorf("Cloudflare not in detected: %v", detected)
	}
	if evidence["Cloudflare"] == "" {
		t.Error("missing evidence for Cloudflare")
	}
}

func TestDetectSQLi(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		switch q {
		case "1":
			w.Write([]byte("Item: 1 <b>ok</b>"))
		case "1' AND '1'='1":
			w.Write([]byte("Item: 1 <b>ok</b>")) // truthy → normal page
		case "1' AND '1'='2":
			w.Write([]byte("Item: 1")) // falsy → different page
		default:
			w.Write([]byte("error: sql syntax")) // error marker
		}
	}))
	defer srv.Close()

	fs := detectSQLi(srv.Client(), srv.URL+"?id=1", 30*time.Second)
	if len(fs) == 0 {
		t.Fatal("expected a SQLi candidate on param id")
	}
	if fs[0].Target == "" || fs[0].Title == "" {
		t.Errorf("malformed finding: %+v", fs[0])
	}
}

func TestDetectSQLi_NoParams(t *testing.T) {
	sg, err := scope.New(scope.ScopeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer sg.Close()
	if fs := detectSQLi(sg.Client(), "https://example.com/static", time.Second); len(fs) != 0 {
		t.Errorf("no params should yield no findings, got %d", len(fs))
	}
}

func TestValidateDomain(t *testing.T) {
	env := &Env{Scope: newTestWebScope(t, scope.ScopeConfig{AllowedDomains: []string{"example.com"}})}
	ok, e := validateDomainWithEnv(env, "https://Example.com/path")
	if e != nil || ok != "Example.com" {
		t.Errorf("got %q, err %v", ok, e)
	}
	if _, e := validateDomainWithEnv(env, ""); e == nil {
		t.Error("empty domain should be rejected")
	}
}

func TestWordlistPath(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	if p := wordlistPath(); p != "" {
		t.Errorf("wordlistPath without config dir should be empty, got %q", p)
	}
	p, cleanup, err := ensureWordlistFile()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !strings.Contains(p, "wordlist") {
		t.Errorf("unexpected wordlist path: %q", p)
	}
}

// ————— community templates —————

// templatesZip builds a source archive shaped like the GitHub tag archive:
// every entry lives under a single root folder.
func templatesZip(t *testing.T, root string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(root + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// templatesServer serves the template archive and the vendor checksums file.
func templatesServer(t *testing.T, archive []byte, publishedSum string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.0.zip", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write(archive)
	})
	mux.HandleFunc("/projectdiscovery/nuclei-templates/releases/download/v10.4.0/nuclei-templates-10.4.0_checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  nuclei-templates-10.4.0.zip\n", publishedSum)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func templatesSpec(sum string) *BinarySpec {
	return &BinarySpec{
		Name:    "nuclei-templates",
		Repo:    "projectdiscovery/nuclei-templates",
		Version: "v10.4.0",
		Bin:     "nuclei-templates",
		Archive: "zip",
		Kind:    "templates",
		SHA256:  sum,
	}
}

func sumOf(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestEnsureTemplates_Idempotent(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")

	archive := templatesZip(t, "nuclei-templates-10.4.0", map[string]string{
		"http/cves/2021/CVE-2021-1234.yaml": "id: cve-2021-1234\n",
		"helpers/generic.yaml":              "id: helper\n",
	})
	sum := sumOf(archive)
	srv, hits := templatesServer(t, archive, sum)

	oldBase := githubArchiveBase
	githubArchiveBase = srv.URL
	defer func() { githubArchiveBase = oldBase }()

	d := NewDownloader(t.TempDir())
	d.Client = srv.Client()

	dir, version, updated, err := d.EnsureTemplates(context.Background(), templatesSpec(sum))
	if err != nil {
		t.Fatalf("EnsureTemplates failed: %v", err)
	}
	if !updated {
		t.Error("first call must report updated=true")
	}
	if version != "v10.4.0" {
		t.Errorf("version = %q, want v10.4.0", version)
	}
	if filepath.Base(dir) != "v10.4.0" {
		t.Errorf("templates dir = %q, want a versioned subdirectory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "http", "cves", "2021", "CVE-2021-1234.yaml")); err != nil {
		t.Errorf("template tree was not extracted: %v", err)
	}
	if got := TemplatesSHA256(dir); got != sum {
		t.Errorf("recorded sha256 = %q, want %q", got, sum)
	}

	// second call must not download again
	dir2, version2, updated2, err := d.EnsureTemplates(context.Background(), templatesSpec(sum))
	if err != nil {
		t.Fatalf("second EnsureTemplates failed: %v", err)
	}
	if updated2 {
		t.Error("second call must report updated=false")
	}
	if dir2 != dir || version2 != version {
		t.Errorf("second call returned %q/%q, want %q/%q", dir2, version2, dir, version)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("archive downloaded %d times, want 1", n)
	}
}

func TestEnsureTemplates_ChecksumMismatch(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")

	archive := templatesZip(t, "nuclei-templates-10.4.0", map[string]string{"http/a.yaml": "id: a\n"})
	sum := sumOf(archive)
	srv, _ := templatesServer(t, archive, sum)

	oldBase := githubArchiveBase
	githubArchiveBase = srv.URL
	defer func() { githubArchiveBase = oldBase }()

	toolsDir := t.TempDir()
	d := NewDownloader(toolsDir)
	d.Client = srv.Client()

	wrong := strings.Repeat("0", 64)
	_, _, _, err := d.EnsureTemplates(context.Background(), templatesSpec(wrong))
	if err == nil {
		t.Fatal("expected a checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(toolsDir, "nuclei-templates", "v10.4.0", templatesVersionFile)); statErr == nil {
		t.Error("a failed install must not leave a version marker behind")
	}
}

func TestEnsureTemplates_PublishedChecksumMismatch(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")

	archive := templatesZip(t, "nuclei-templates-10.4.0", map[string]string{"http/a.yaml": "id: a\n"})
	sum := sumOf(archive)
	srv, _ := templatesServer(t, archive, strings.Repeat("1", 64))

	oldBase := githubArchiveBase
	githubArchiveBase = srv.URL
	defer func() { githubArchiveBase = oldBase }()

	d := NewDownloader(t.TempDir())
	d.Client = srv.Client()

	_, _, _, err := d.EnsureTemplates(context.Background(), templatesSpec(sum))
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected the published checksum to be enforced, got %v", err)
	}
}

func TestEnsureTemplates_Unreachable(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "")

	srv, _ := templatesServer(t, []byte("not a zip"), strings.Repeat("2", 64))
	base := srv.URL
	srv.Close()

	oldBase := githubArchiveBase
	githubArchiveBase = base
	defer func() { githubArchiveBase = oldBase }()

	toolsDir := t.TempDir()
	d := NewDownloader(toolsDir)

	dir, _, updated, err := d.EnsureTemplates(context.Background(), templatesSpec(strings.Repeat("3", 64)))
	if err == nil {
		t.Fatal("expected an error when the archive cannot be downloaded")
	}
	if updated || dir != "" {
		t.Errorf("no templates should be reported on failure: dir=%q updated=%v", dir, updated)
	}
	if _, statErr := os.Stat(filepath.Join(toolsDir, "nuclei-templates")); statErr == nil {
		t.Error("no templates directory should be created on failure")
	}
}

func TestEnsureTemplates_DisabledDownloads(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "1")

	d := NewDownloader(t.TempDir())
	_, _, _, err := d.EnsureTemplates(context.Background(), templatesSpec(strings.Repeat("4", 64)))
	if err == nil || !strings.Contains(err.Error(), "downloads are disabled") {
		t.Fatalf("expected a disabled-download error, got %v", err)
	}
}

func TestTemplatesArchiveNaming(t *testing.T) {
	spec := templatesSpec("")
	if got := templatesArchiveName(spec); got != "nuclei-templates-10.4.0.zip" {
		t.Errorf("archive name = %q", got)
	}
	if got := templatesArchiveURL(spec); !strings.HasSuffix(got, "/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.0.zip") {
		t.Errorf("archive url = %q", got)
	}
	if got := templatesChecksumsURL(spec); !strings.HasSuffix(got, "/releases/download/v10.4.0/nuclei-templates-10.4.0_checksums.txt") {
		t.Errorf("checksums url = %q", got)
	}
}
