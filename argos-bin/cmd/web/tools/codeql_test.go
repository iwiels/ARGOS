package tools

import (
	"archive/zip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// The CodeQL CLI is not installed in every environment: the tool must say so
// instead of failing silently.
func TestCodeQLUnavailableIsReportedClearly(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv(disableDownloadEnv, "1")

	out := codeqlRun(testContext(t), nil, codeqlOptions{Path: t.TempDir()})
	if out.Available {
		t.Fatal("the CLI is not installed: the run must degrade")
	}
	if out.Reason == "" {
		t.Fatal("the degradation must explain why the CLI is not available")
	}
	if out.Findings != nil {
		t.Fatalf("an unavailable CLI must not report findings: %v", out.Findings)
	}
}

func TestCodeQLInstallHintIsExplicit(t *testing.T) {
	hint := codeqlInstallHint()
	if !strings.Contains(hint, "codeql-cli-binaries") {
		t.Errorf("the install hint does not point to the release: %q", hint)
	}
	if !strings.Contains(strings.ToLower(hint), "terms of service") {
		t.Errorf("the install hint does not mention the distribution terms: %q", hint)
	}
}

func TestCodeQLLanguageDetection(t *testing.T) {
	root := t.TempDir()
	writeSourceFile(t, filepath.Join(root, "src", "api.ts"), "export const x = 1\n")
	writeSourceFile(t, filepath.Join(root, "src", "db.ts"), "export const y = 2\n")
	writeSourceFile(t, filepath.Join(root, "app", "main.py"), "print(1)\n")
	writeSourceFile(t, filepath.Join(root, "node_modules", "dep", "index.js"), "module.exports = 1\n")

	counts := detectCodeqlLanguages(root)
	if counts["javascript-typescript"] != 2 {
		t.Errorf("javascript files = %d, want 2 (the vendor directory must be skipped)", counts["javascript-typescript"])
	}
	if counts["python"] != 1 {
		t.Errorf("python files = %d, want 1", counts["python"])
	}
	if counts["javascript-typescript"]+counts["python"] == 0 {
		t.Fatal("no language detected")
	}

	lang, ok := codeqlPickLanguage(root, "", nil)
	if !ok {
		t.Fatal("no language picked")
	}
	if lang.ID != "javascript-typescript" {
		t.Errorf("language = %q, want the dominant one", lang.ID)
	}
}

func TestCodeQLLanguageAliases(t *testing.T) {
	for alias, want := range map[string]string{
		"js":         "javascript-typescript",
		"typescript": "javascript-typescript",
		"java":       "java-kotlin",
		"kotlin":     "java-kotlin",
		"c++":        "c-cpp",
		"cpp":        "c-cpp",
		"c#":         "csharp",
		"python":     "python",
	} {
		lang, ok := codeqlLanguageOf(alias)
		if !ok {
			t.Errorf("the alias %q was not resolved", alias)
			continue
		}
		if lang.ID != want {
			t.Errorf("the alias %q resolved to %q, want %q", alias, lang.ID, want)
		}
	}
	if _, ok := codeqlLanguageOf("php"); ok {
		t.Error("CodeQL has no PHP extractor: it must not be offered")
	}
}

// The resolver decides what the CLI can analyze: a language without an
// extractor is not an option even when the tree is written in it.
func TestCodeQLPickLanguageSkipsUnavailableExtractors(t *testing.T) {
	root := t.TempDir()
	writeSourceFile(t, filepath.Join(root, "main.py"), "print(1)\n")
	writeSourceFile(t, filepath.Join(root, "index.ts"), "export const x = 1\n")

	resolved := map[string]bool{"javascript": true}
	lang, ok := codeqlPickLanguage(root, "", resolved)
	if !ok {
		t.Fatal("no language picked")
	}
	if lang.ID != "javascript-typescript" {
		t.Errorf("language = %q, want the one the CLI can analyze", lang.ID)
	}
}

func TestCodeQLResolveLanguagesParsesJSON(t *testing.T) {
	resolved := codeqlResolveLanguages(`{"javascript":["/opt/codeql/javascript"],"python":["/opt/codeql/python"]}`)
	if !resolved["javascript"] || !resolved["python"] {
		t.Fatalf("the resolver output was not parsed: %v", resolved)
	}
	if resolved["go"] {
		t.Error("the resolver reported a language it did not declare")
	}
}

func TestCodeQLResolveLanguagesToleratesABanner(t *testing.T) {
	resolved := codeqlResolveLanguages("CodeQL CLI banner\n{\"python\":[\"/opt/codeql/python\"]}")
	if !resolved["python"] {
		t.Fatalf("the resolver output was not parsed: %v", resolved)
	}
}

func TestCodeQLDatabaseArgs(t *testing.T) {
	args := codeqlDatabaseArgs("/tmp/db", "/src", "javascript-typescript", "")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "database create") {
		t.Errorf("args = %v, want the database create command", args)
	}
	if !strings.Contains(joined, "--language=javascript-typescript") {
		t.Errorf("args = %v, want the language", args)
	}
	if !strings.Contains(joined, "--source-root=/src") {
		t.Errorf("args = %v, want the source root", args)
	}
	if !strings.Contains(joined, "--overwrite") {
		t.Errorf("args = %v, want --overwrite", args)
	}
	if !strings.Contains(joined, "--build-mode=none") {
		t.Errorf("args = %v, an interpreted language needs no build", args)
	}
	if args[len(args)-1] != "/tmp/db" {
		t.Errorf("args = %v, the database must be the last argument", args)
	}

	compiled := strings.Join(codeqlDatabaseArgs("/tmp/db", "/src", "java-kotlin", ""), " ")
	if strings.Contains(compiled, "--build-mode=none") {
		t.Errorf("args = %v, a compiled language needs a build", compiled)
	}

	withBuild := strings.Join(codeqlDatabaseArgs("/tmp/db", "/src", "java-kotlin", "mvn -B package"), " ")
	if !strings.Contains(withBuild, "--command=mvn -B package") {
		t.Errorf("args = %v, want the build command", withBuild)
	}
}

func TestCodeQLPhasesShareTheReadOnlySourceAndArtifactWorkspace(t *testing.T) {
	sourceRoot := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	dbPath := filepath.Join(workspace, "codeql-db")
	reportPath := filepath.Join(workspace, "results.sarif")
	timeout := 3 * time.Minute

	create := codeqlArtifactRunOptions(codeqlDatabaseArgs(dbPath, sourceRoot, "javascript-typescript", ""), sourceRoot, workspace, timeout)
	analyze := codeqlArtifactRunOptions(codeqlAnalyzeArgs(dbPath, reportPath, []string{"codeql/javascript-queries:security-extended"}), sourceRoot, workspace, timeout)
	for name, options := range map[string]runOptions{"database create": create, "database analyze": analyze} {
		if options.Dir != sourceRoot || options.ArtifactDir != workspace || options.Timeout != timeout {
			t.Errorf("%s worker mounts = dir %q artifacts %q timeout %s", name, options.Dir, options.ArtifactDir, options.Timeout)
		}
	}
}

func TestCodeQLAnalyzeArgs(t *testing.T) {
	queries := []string{"codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"}
	args := codeqlAnalyzeArgs("/tmp/db", "/tmp/out.sarif", queries)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "database analyze") {
		t.Errorf("args = %v, want the database analyze command", args)
	}
	if !strings.Contains(joined, "--format=sarif-latest") {
		t.Errorf("args = %v, want the SARIF output", args)
	}
	if !strings.Contains(joined, "--output=/tmp/out.sarif") {
		t.Errorf("args = %v, want the output file", args)
	}
	if !strings.Contains(joined, "--download") {
		t.Errorf("args = %v, the query packs must be downloadable", args)
	}
	if !strings.Contains(joined, "/tmp/db") {
		t.Errorf("args = %v, want the database", args)
	}
	if !strings.Contains(joined, queries[0]) {
		t.Errorf("args = %v, want the query specifier", args)
	}
}

func TestSemgrepRunOptionsUseReadOnlySourceAndSeparateArtifacts(t *testing.T) {
	sourceRoot := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	artifactDir := t.TempDir()
	reportPath := filepath.Join(artifactDir, "results.sarif")
	timeout := 30 * time.Second
	options := semgrepArtifactRunOptions("p/security-audit", sourceRoot, reportPath, timeout)
	if options.Dir != sourceRoot || options.ArtifactDir != artifactDir || options.Timeout != timeout {
		t.Fatalf("Semgrep worker paths = source %q, artifacts %q, timeout %s", options.Dir, options.ArtifactDir, options.Timeout)
	}
	joined := strings.Join(options.Args, " ")
	if !strings.Contains(joined, "--output "+reportPath) || !strings.HasSuffix(joined, sourceRoot) {
		t.Fatalf("Semgrep source/report paths were not retained: %s", joined)
	}
}

func TestCodeQLDefaultQuerySuites(t *testing.T) {
	lang, _ := codeqlLanguageOf("javascript")
	queries := codeqlQueries(lang, "")
	if len(queries) != 2 {
		t.Fatalf("queries = %v, want the two security suites", queries)
	}
	if !strings.Contains(queries[0], "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls") {
		t.Errorf("queries = %v, want the security-extended suite", queries)
	}
	if !strings.Contains(queries[1], "security-and-quality") {
		t.Errorf("queries = %v, want the security-and-quality suite", queries)
	}

	custom := codeqlQueries(lang, "security-extended")
	if len(custom) != 1 || !strings.Contains(custom[0], "javascript-security-extended.qls") {
		t.Errorf("queries = %v, want only the requested suite", custom)
	}

	verbatim := codeqlQueries(lang, "octo-org/my-pack:suites/custom.qls")
	if len(verbatim) != 1 || verbatim[0] != "octo-org/my-pack:suites/custom.qls" {
		t.Errorf("queries = %v, a full specifier must be used as it is", verbatim)
	}
}

// The whole point of CodeQL: a cross-file finding carries the dataflow of
// the value from the source to the sink.
func TestCodeQLSARIFProducesAFindingWithCWEAndDataflow(t *testing.T) {
	sarif := `{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": { "driver": { "name": "CodeQL", "rules": [
	      { "id": "js/missing-authorization",
	        "name": "MissingAuthorization",
	        "shortDescription": { "text": "Missing authorization check" },
	        "helpUri": "https://codeql.github.com/codeql-query-help/javascript/js/missing-authorization/",
	        "defaultConfiguration": { "level": "error" },
	        "properties": { "tags": ["security", "external/cwe/cwe-862"], "precision": "high", "security-severity": "7.5" } }
	    ] } },
	    "results": [{
	      "ruleId": "js/missing-authorization",
	      "ruleIndex": 0,
	      "level": "error",
	      "message": { "text": "This route handler does not check that the user owns the requested document." },
	      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/routes/documents.js" }, "region": { "startLine": 42, "endLine": 44 } } }],
	      "codeFlows": [{
	        "threadFlows": [{
	          "locations": [
	            { "location": { "physicalLocation": { "artifactLocation": { "uri": "src/routes/documents.js" }, "region": { "startLine": 42 } } }, "importance": "essential" },
	            { "location": { "physicalLocation": { "artifactLocation": { "uri": "src/db/documents.js" }, "region": { "startLine": 118 } } }, "importance": "essential" }
	          ]
	        }]
	      }]
	    }]
	  }]
	}`

	findings, err := parseSarifReport([]byte(sarif), "code.semantic")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	findings = codeqlFindings(findings, codeqlLanguage{ID: "javascript-typescript", Pack: "javascript"})
	f := findings[0]

	if f.SourceTool != "code.semantic" {
		t.Errorf("source tool = %q, want code.semantic", f.SourceTool)
	}
	if f.RuleID != "codeql:js/missing-authorization" {
		t.Errorf("rule id = %q, want the codeql prefix", f.RuleID)
	}
	if f.CWE != "CWE-862" {
		t.Errorf("cwe = %q, want CWE-862", f.CWE)
	}
	if f.Vector != "src/routes/documents.js:42" {
		t.Errorf("vector = %q, want file:line", f.Vector)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (the query declares 7.5)", f.Severity)
	}
	flow, _ := f.Evidence["dataflow"].([]map[string]any)
	if len(flow) != 2 {
		t.Fatalf("dataflow = %v, want the two steps of the cross-file path", f.Evidence["dataflow"])
	}
	if flow[1]["file"] != "src/db/documents.js" {
		t.Errorf("the dataflow does not reach the other file: %v", flow)
	}
	if !containsString(f.Tags, "semantic-analysis") {
		t.Errorf("tags = %v, want the semantic analysis tag", f.Tags)
	}
}

// The fusion of the engines: the same weakness at the same place is one
// finding, and both engines stay attributed.
func TestCodeMergeFindingsDeduplicates(t *testing.T) {
	semgrep := Finding{
		Source:     "code.sast",
		SourceTool: "code.sast",
		RuleID:     "semgrep:javascript.lang.security.audit.xss",
		CWE:        "CWE-79",
		Target:     "src/app.js",
		Vector:     "src/app.js:10",
		Severity:   SeverityHigh,
		Confidence: ConfidenceProbable,
		Evidence:   map[string]any{"line": 10, "rule": "xss"},
	}
	codeql := Finding{
		Source:     "code.semantic",
		SourceTool: "code.semantic",
		RuleID:     "codeql:js/xss",
		CWE:        "CWE-79",
		Target:     "src/app.js",
		Vector:     "src/app.js:10",
		Severity:   SeverityCritical,
		Confidence: ConfidenceConfirmed,
		Evidence:   map[string]any{"line": 10, "rule": "js/xss", "dataflow": []map[string]any{{"file": "src/app.js"}}},
	}
	other := Finding{
		Source:     "code.semantic",
		SourceTool: "code.semantic",
		RuleID:     "codeql:js/sql-injection",
		CWE:        "CWE-89",
		Target:     "src/db.js",
		Vector:     "src/db.js:20",
		Severity:   SeverityHigh,
		Evidence:   map[string]any{"line": 20},
	}

	merged := codeMergeFindings([]Finding{semgrep}, []Finding{codeql, other})
	if len(merged) != 2 {
		t.Fatalf("merged = %d findings, want 2", len(merged))
	}
	if merged[0].SourceTool != "code.sast" {
		t.Errorf("the source tool of the merged finding = %q, want the first engine", merged[0].SourceTool)
	}
	if merged[0].Severity != SeverityCritical {
		t.Errorf("the merged severity = %q, want the highest", merged[0].Severity)
	}
	tools := codeEngineList(merged[0].Evidence["sourceTools"])
	if !containsString(tools, "code.sast") || !containsString(tools, "code.semantic") {
		t.Errorf("the merged finding lost the attribution of an engine: %v", tools)
	}
	if merged[0].Evidence["dataflow"] == nil {
		t.Error("the merged finding lost the dataflow of the second engine")
	}
	if merged[1].SourceTool != "code.semantic" {
		t.Errorf("the finding of the second engine = %q, want code.semantic", merged[1].SourceTool)
	}
}

// The end to end of the tool: the list of the tools has to carry the new
// entries.
func TestCodeQLToolsAreRegistered(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	s := newTestServer(t)
	names := map[string]bool{}
	for _, def := range s.ToolDefinitions() {
		names[def.Name] = true
	}
	for _, want := range []string{"code.semantic", "code.analyze", "code.sbom"} {
		if !names[want] {
			t.Errorf("the tool %q is not registered", want)
		}
	}
}

// The degradation of code.semantic is a result, not an error: the agent
// must be able to read why the engine did not run.
func TestCodeQLSemanticToolDegradesWithoutTheCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv(disableDownloadEnv, "1")
	t.Setenv(codeqlTermsAcceptedEnv, "")

	s := newTestServer(t)
	result, _ := callTool(t, s, "code.semantic", map[string]any{"path": t.TempDir()})
	res, _ := result.(map[string]interface{})
	if res == nil {
		t.Fatal("the tool did not return a result")
	}
	if res["status"] != "unavailable" {
		t.Errorf("status = %v, want unavailable", res["status"])
	}
	if res["reason"] == nil || res["reason"] == "" {
		t.Error("the result does not explain why the CLI is not available")
	}
	if res["install_hint"] == nil || res["install_hint"] == "" {
		t.Error("the result does not tell how to install the CLI")
	}
}

func TestCodeQLSemanticToolRejectsAnUnknownLanguage(t *testing.T) {
	t.Setenv("OPENCODE_CONFIG_DIR", "")

	s := newTestServer(t)
	_, errObj := callToolRaw(t, s, "code.semantic", map[string]any{"language": "cobol"})
	if errObj == nil {
		t.Fatal("an unsupported language must be rejected")
	}
	if !strings.Contains(errObj.Message, "cobol") {
		t.Errorf("the error does not name the language: %q", errObj.Message)
	}
}

func TestCodeQLClampTimeout(t *testing.T) {
	if got := clampTimeoutRange(0, codeqlDefaultTimeout, codeqlMaxTimeout); got != 600 {
		t.Errorf("the default timeout = %d, want 600", got)
	}
	if got := clampTimeoutRange(5000, codeqlDefaultTimeout, codeqlMaxTimeout); got != 1800 {
		t.Errorf("the clamped timeout = %d, want 1800", got)
	}
	if got := clampTimeoutRange(120, codeqlDefaultTimeout, codeqlMaxTimeout); got != 120 {
		t.Errorf("the timeout = %d, want 120", got)
	}
}

func TestCodeQLUseRequiresExplicitTermsEligibility(t *testing.T) {
	t.Setenv(codeqlTermsAcceptedEnv, "")
	if codeqlUseAllowed() {
		t.Fatal("CodeQL should stay disabled until the operator confirms eligible use")
	}

	t.Setenv(codeqlTermsAcceptedEnv, "TRUE")
	if !codeqlUseAllowed() {
		t.Fatal("the explicit true setting should enable CodeQL for eligible use")
	}
}

// The release of the CodeQL CLI publishes one archive per platform and a
// sha256 digest next to each of them: the downloader has to pick the digest
// of the archive it downloaded, not the first one of the release.
func TestCodeQLAssetSelectionUsesThePublishedNames(t *testing.T) {
	assets := []string{
		"codeql-linux64.zip",
		"codeql-linux64.zip.checksum.txt",
		"codeql-osx64.zip",
		"codeql-osx64.zip.checksum.txt",
		"codeql-win64.zip",
		"codeql-win64.zip.checksum.txt",
		"codeql.zip",
	}

	for _, archive := range []string{"codeql-win64.zip", "codeql-linux64.zip", "codeql-osx64.zip"} {
		checksum := pickChecksumAssetFor(assets, archive)
		if checksum != archive+".checksum.txt" {
			t.Errorf("the checksum of %s = %q, want %q", archive, checksum, archive+".checksum.txt")
		}
	}

	// the digest the vendor publishes: "<sha256>  <archive>"
	const digest = "10fcb55f564ceb7152e6788b704ca3918f7575dc9fe1b291f61a2135fdbe9378"
	parsed := checksumFor("codeql-win64.zip", digest+"  codeql-win64.zip\n")
	if parsed != digest {
		t.Errorf("the published digest was not parsed: %q", parsed)
	}
}

// The downloader has to resolve the release of the CodeQL CLI: one asset
// per platform and the digest that names it.
func TestCodeQLResolveReleasePicksThePlatformAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v2.20.7",
			"assets": []map[string]any{
				{"name": "codeql-linux64.zip", "browser_download_url": "https://example.test/codeql-linux64.zip"},
				{"name": "codeql-linux64.zip.checksum.txt", "browser_download_url": "https://example.test/codeql-linux64.zip.checksum.txt"},
				{"name": "codeql-osx64.zip", "browser_download_url": "https://example.test/codeql-osx64.zip"},
				{"name": "codeql-osx64.zip.checksum.txt", "browser_download_url": "https://example.test/codeql-osx64.zip.checksum.txt"},
				{"name": "codeql-win64.zip", "browser_download_url": "https://example.test/codeql-win64.zip"},
				{"name": "codeql-win64.zip.checksum.txt", "browser_download_url": "https://example.test/codeql-win64.zip.checksum.txt"},
				{"name": "codeql.zip", "browser_download_url": "https://example.test/codeql.zip"},
			},
		})
	}))
	defer srv.Close()

	previous := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = previous }()

	var spec *BinarySpec
	for i := range binSpecs {
		if binSpecs[i].Name == "codeql" {
			spec = &binSpecs[i]
			break
		}
	}
	if spec == nil {
		t.Fatal("the codeql spec is missing")
	}

	d := NewDownloader(t.TempDir())
	d.Client = srv.Client()
	rel, err := d.resolveRelease(context.Background(), spec)
	if err != nil {
		t.Fatalf("resolveRelease failed: %v", err)
	}

	targetOS := d.effectiveOS()
	token, ok := spec.AssetPlatforms[targetOS]
	if !ok {
		t.Skipf("the CodeQL CLI has no build for %s", targetOS)
	}
	want := "codeql-" + token + ".zip"
	if rel.archiveName != want {
		t.Errorf("archive = %q, want %q", rel.archiveName, want)
	}
	if !strings.HasSuffix(rel.checksumURL, want+".checksum.txt") {
		t.Errorf("checksum = %q, want the digest of %q", rel.checksumURL, want)
	}
	if rel.archiveType != "zip" {
		t.Errorf("archive type = %q, want zip", rel.archiveType)
	}
}

// The CodeQL CLI is a tree, not an executable: the launcher needs the
// sibling directories the bundle ships.
func TestInstallBundleTreeKeepsTheWholeTree(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "codeql.zip")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatalf("cannot create the archive: %v", err)
	}
	zw := zip.NewWriter(file)
	for name, content := range map[string]string{
		"codeql/codeql.exe":    "launcher",
		"codeql/codeql.cmd":    "launcher",
		"codeql/python/lib.py": "extractor",
		"codeql/tools/ql.jar":  "tools",
		"codeql/qlpacks/a.yml": "packs",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("cannot add %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("cannot write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("cannot close the archive: %v", err)
	}
	file.Close()

	dest := filepath.Join(t.TempDir(), "codeql")
	if err := installBundleTree(archive, "zip", dest); err != nil {
		t.Fatalf("installBundleTree failed: %v", err)
	}
	for _, name := range []string{"codeql.exe", "codeql.cmd", "python/lib.py", "tools/ql.jar", "qlpacks/a.yml"} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(name))); err != nil {
			t.Errorf("the bundle lost %s: %v", name, err)
		}
	}
}

// The spec of CodeQL has to name the release the CLI is downloaded from and
// the platform assets it publishes.
func TestCodeQLSpecIsComplete(t *testing.T) {
	var spec *BinarySpec
	for i := range binSpecs {
		if binSpecs[i].Name == "codeql" {
			spec = &binSpecs[i]
			break
		}
	}
	if spec == nil {
		t.Fatal("the codeql spec is missing")
	}
	if spec.Repo != "github/codeql-cli-binaries" {
		t.Errorf("repo = %q", spec.Repo)
	}
	if spec.Archive != "zip" {
		t.Errorf("archive = %q, want zip", spec.Archive)
	}
	if spec.AssetTemplate != "codeql-{platform}.zip" {
		t.Errorf("asset template = %q", spec.AssetTemplate)
	}
	if spec.AssetPlatforms["windows"] != "win64" || spec.AssetPlatforms["darwin"] != "osx64" || spec.AssetPlatforms["linux"] != "linux64" {
		t.Errorf("the platform assets do not match the published ones: %v", spec.AssetPlatforms)
	}
	if !spec.RequireChecksum {
		t.Error("the CodeQL release publishes a digest per asset: it must be required")
	}
	if spec.downloadLimit() <= defaultDownloadLimit {
		t.Error("the CodeQL bundle does not fit in the default size cap")
	}
}

// writeFile writes a file, creating its directory.
func writeSourceFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("cannot create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
}

// testContext returns a context for the tool calls.
func testContext(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

// newTestServer registers every tool of the web server.
func newTestServer(t *testing.T) *mcp.Server {
	t.Helper()
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	s := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "1.0.0"})
	RegisterAll(s, NewEnv(t.TempDir()))
	return s
}

// callTool invokes a tool and returns its result.
func callTool(t *testing.T, s *mcp.Server, name string, params map[string]any) (interface{}, *mcp.ErrorObj) {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("cannot encode the params: %v", err)
	}
	return s.GetToolHandler(name)(mcp.ToolContext{Ctx: context.Background()}, raw)
}

// callToolRaw invokes a tool and returns its result.
func callToolRaw(t *testing.T, s *mcp.Server, name string, params map[string]any) (interface{}, *mcp.ErrorObj) {
	t.Helper()
	return callTool(t, s, name, params)
}

func TestCodeAnalyzeStatusReportsPartialAndFailedRuns(t *testing.T) {
	for _, test := range []struct {
		semgrep bool
		codeql  bool
		want    string
	}{
		{semgrep: true, codeql: true, want: "completed"},
		{semgrep: true, codeql: false, want: "partial"},
		{semgrep: false, codeql: true, want: "partial"},
		{semgrep: false, codeql: false, want: "error"},
	} {
		if got := codeAnalyzeStatus(test.semgrep, test.codeql); got != test.want {
			t.Errorf("codeAnalyzeStatus(%v, %v) = %q, want %q", test.semgrep, test.codeql, got, test.want)
		}
	}
}
