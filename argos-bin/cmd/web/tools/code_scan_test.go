package tools

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSarifOutput(t *testing.T) {
	mockSarif := `{
		"version": "2.1.0",
		"runs": [{
			"tool": { "driver": { "name": "semgrep" } },
			"results": [{
				"ruleId": "hardcoded-secret",
				"level": "error",
				"message": { "text": "Hardcoded AWS secret key detected" },
				"locations": [{ "physicalLocation": { "artifactLocation": { "uri": "app.py" } } }]
			}]
		}]
	}`
	findings, err := parseSarifReport([]byte(mockSarif), "code.sast")
	if err != nil {
		t.Fatalf("parseSarifReport failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].Source != "code.sast" {
		t.Fatalf("expected source code.sast, got %s", findings[0].Source)
	}
}

func TestParseGitleaksJson(t *testing.T) {
	mockGitleaks := `[
		{
			"RuleID": "generic-api-key",
			"Description": "Generic API Key",
			"File": "config.js",
			"StartLine": 12,
			"Secret": "1234567890abcdef",
			"Match": "key = 1234567890abcdef"
		}
	]`
	findings, err := parseGitleaksJSON([]byte(mockGitleaks))
	if err != nil {
		t.Fatalf("parseGitleaksJSON failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity for secrets, got %s", findings[0].Severity)
	}
}

func TestParseGitleaksJSONRejectsNonArrayReports(t *testing.T) {
	for _, report := range []string{"", "null", "{}"} {
		if _, err := parseGitleaksJSON([]byte(report)); err == nil {
			t.Errorf("report %q was accepted as a clean scan", report)
		}
	}
}

// The secret must never reach the backend in clear: the report is stored,
// indexed and shown to the operator.
func TestParseGitleaksNeverLeaksTheSecret(t *testing.T) {
	const secret = "AKIAQWERTYUIOPASDFGH"
	report := `[{
		"RuleID": "aws-access-token",
		"Description": "AWS Access Token",
		"File": "config.js",
		"StartLine": 12,
		"Secret": "` + secret + `",
		"Match": "aws_key = \"` + secret + `\"",
		"Commit": "deadbeef",
		"Entropy": 3.9,
		"Fingerprint": "deadbeef:config.js:aws-access-token:12"
	}]`

	findings, err := parseGitleaksJSON([]byte(report))
	if err != nil {
		t.Fatalf("parseGitleaksJSON failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	encoded, err := json.Marshal(findings[0].ToMap())
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("the finding leaks the secret in clear: %s", encoded)
	}

	evidence := findings[0].Evidence
	if evidence["secret"] == secret {
		t.Error("the masked secret must not be the value")
	}
	if masked, _ := evidence["secret"].(string); !strings.Contains(masked, "...") {
		t.Errorf("the masked secret = %q, want a masked prefix", masked)
	}
	hash, _ := evidence["secretHash"].(string)
	if len(hash) != 64 {
		t.Errorf("secretHash = %q, want a sha256 digest", hash)
	}
	if match, _ := evidence["match"].(string); strings.Contains(match, secret) {
		t.Errorf("the match leaks the secret: %q", match)
	}
	if findings[0].Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q for a high confidence rule", findings[0].Confidence, ConfidenceConfirmed)
	}
}

// A generic rule only matches a shape: it stays "probable".
func TestGitleaksConfidencePerRule(t *testing.T) {
	if got := gitleaksConfidence("generic-api-key"); got != ConfidenceProbable {
		t.Errorf("confidence(generic-api-key) = %q, want %q", got, ConfidenceProbable)
	}
	if got := gitleaksConfidence("private-key"); got != ConfidenceConfirmed {
		t.Errorf("confidence(private-key) = %q, want %q", got, ConfidenceConfirmed)
	}
}

func TestMaskSecret(t *testing.T) {
	if got := maskSecret("AKIAQWERTYUIOPASDFGH"); got != "AKIA...DFGH" {
		t.Errorf("maskSecret = %q", got)
	}
	if got := maskSecret("short"); got != "***" {
		t.Errorf("maskSecret(short) = %q, want a full mask", got)
	}
	if got := maskSecret("REDACTED"); got != "***" {
		t.Errorf("maskSecret(REDACTED) = %q", got)
	}
	if got := maskSecret(""); got != "" {
		t.Errorf("maskSecret(empty) = %q", got)
	}
}

func TestGitleaksRunFailed(t *testing.T) {
	// A clean scan: no leaks, exit code 0 and a report.
	if gitleaksRunFailed(&runResult{ExitCode: 0}, true) {
		t.Error("a clean scan is not a failure")
	}
	// Leaks found: gitleaks exits with 1 and writes the report.
	if gitleaksRunFailed(&runResult{ExitCode: 1}, true) {
		t.Error("a scan with leaks is not a failure")
	}
	// A flag error: exit code 126.
	if !gitleaksRunFailed(&runResult{ExitCode: 126}, false) {
		t.Error("an unknown flag is a failure")
	}
	// The path is not a repository: gitleaks exits with 1 and says so.
	if !gitleaksRunFailed(&runResult{ExitCode: 1, Stderr: "failed to scan Git repository"}, true) {
		t.Error("a failed scan is a failure")
	}
	if !gitleaksRunFailed(&runResult{ExitCode: 1}, false) {
		t.Error("a run without report did not scan anything")
	}
}

func TestGitleaksArgs(t *testing.T) {
	args := gitleaksArgs(gitleaksModeGit, "/repo", "/tmp/report.json")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "git") {
		t.Errorf("args = %v, want the git mode", args)
	}
	if !strings.Contains(joined, "--redact") {
		t.Errorf("args = %v, want --redact", args)
	}
	if !strings.Contains(joined, "--report-format json") {
		t.Errorf("args = %v, want the json report", args)
	}
	if !strings.Contains(joined, "--no-banner") {
		t.Errorf("args = %v, want --no-banner", args)
	}

	dirArgs := gitleaksArgs(gitleaksModeDir, "/repo", "/tmp/report.json")
	if strings.Join(dirArgs, " ") == joined {
		t.Error("the dir mode must not run the git mode")
	}
}

func TestGitleaksRunOptionsKeepSourceReadOnlyAndReportsSeparate(t *testing.T) {
	opts := gitleaksRunOptions(gitleaksModeDir, "/repo/project", "/tmp/argos-artifacts/report.json", 45*time.Second)
	if opts.Dir != "/repo/project" {
		t.Fatalf("source directory = %q, want /repo/project", opts.Dir)
	}
	wantArtifactDir := filepath.Dir("/tmp/argos-artifacts/report.json")
	if opts.ArtifactDir != wantArtifactDir {
		t.Fatalf("artifact directory = %q, want %q", opts.ArtifactDir, wantArtifactDir)
	}
	if opts.Timeout != 45*time.Second {
		t.Fatalf("timeout = %s, want 45s", opts.Timeout)
	}
	joined := strings.Join(opts.Args, " ")
	if !strings.Contains(joined, "--report-path /tmp/argos-artifacts/report.json") {
		t.Fatalf("report path was not passed to Gitleaks: %s", joined)
	}
}

// The same secret in the working tree and in the history is one finding.
func TestGitleaksMergeDeduplicates(t *testing.T) {
	root := t.TempDir()
	fromHistory := Finding{
		Source:   "code.secrets",
		Target:   "config.js",
		Evidence: map[string]any{"rule": "aws-access-token", "line": 12, "commit": "deadbeef"},
	}
	fromWorkingTree := Finding{
		Source:   "code.secrets",
		Target:   filepath.Join(root, "config.js"),
		Evidence: map[string]any{"rule": "aws-access-token", "line": 12},
	}

	merged := gitleaksMerge(root, []Finding{fromHistory}, []Finding{fromWorkingTree})
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if merged[0].Evidence["commit"] != "deadbeef" {
		t.Errorf("the merged finding lost the commit: %v", merged[0].Evidence)
	}
}

func TestSemgrepArgs(t *testing.T) {
	args := semgrepArgs("", ".", "/tmp/out.sarif")
	joined := strings.Join(args, " ")

	for _, pack := range []string{"p/security-audit", "p/owasp-top-ten", "p/cwe-top-25", "p/trailofbits"} {
		if !strings.Contains(joined, "--config "+pack) {
			t.Errorf("args = %v, want the %s pack", args, pack)
		}
	}
	if strings.Contains(joined, "auto") {
		t.Errorf("args = %v, the auto config is not reproducible", args)
	}
	if !strings.Contains(joined, "--metrics=off") {
		t.Errorf("args = %v, want --metrics=off", args)
	}
	if !strings.Contains(joined, "--dataflow-traces") {
		t.Errorf("args = %v, want --dataflow-traces", args)
	}
	if !strings.Contains(joined, "--sarif") {
		t.Errorf("args = %v, want the sarif output", args)
	}

	override := strings.Join(semgrepArgs("p/default", ".", "/tmp/out.sarif"), " ")
	if !strings.Contains(override, "--config p/default") {
		t.Errorf("args = %v, want the override to win", override)
	}
	if strings.Contains(override, "p/security-audit") {
		t.Errorf("args = %v, the override must replace the default packs", override)
	}
}

func TestTrivyArgs(t *testing.T) {
	joined := strings.Join(trivyArgs(trivyModeFS, ".", "/tmp/out.sarif", "", false), " ")
	if !strings.Contains(joined, "--scanners vuln,secret,misconfig") {
		t.Errorf("args = %v, want the three scanners", joined)
	}
	if !strings.Contains(joined, "--format sarif") {
		t.Errorf("args = %v, want the sarif output", joined)
	}
	if strings.Contains(joined, "--severity") {
		t.Errorf("args = %v, an empty severity must not add the flag", joined)
	}
	if strings.Contains(joined, "--ignore-unfixed") {
		t.Errorf("args = %v, --ignore-unfixed is opt-in", joined)
	}

	filtered := strings.Join(trivyArgs(trivyModeFS, ".", "/tmp/out.sarif", "CRITICAL,HIGH", true), " ")
	if !strings.Contains(filtered, "--severity CRITICAL,HIGH") {
		t.Errorf("args = %v, want the severity filter", filtered)
	}
	if !strings.Contains(filtered, "--ignore-unfixed") {
		t.Errorf("args = %v, want --ignore-unfixed", filtered)
	}
}

func TestTrivyScanMountsRepositoryReadOnlyAndUsesPrivateReportDirectory(t *testing.T) {
	sourceRoot := t.TempDir()
	executor := &captureRunnerExecutor{}
	previous := defaultExecutor
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })

	_, result := trivyScan(context.Background(), "/opt/argos/tools/trivy", trivyModeFS, sourceRoot, "", false, 60)
	if result == nil {
		t.Fatal("Trivy run did not return a result")
	}
	if executor.spec.Dir != sourceRoot {
		t.Fatalf("source directory = %q, want %q", executor.spec.Dir, sourceRoot)
	}
	if executor.spec.ArtifactDir == "" {
		t.Fatal("Trivy report directory was not mounted for the worker")
	}
}

func TestTrivySBOMRunOptionsUseReadOnlySourceAndSeparateReport(t *testing.T) {
	sourceRoot := t.TempDir()
	artifactDir := t.TempDir()
	reportPath := filepath.Join(artifactDir, "sbom.cdx.json")
	timeout := 45 * time.Second
	options := trivySbomRunOptions(trivyModeFS, sourceRoot, sourceRoot, reportPath, timeout)
	if options.Dir != sourceRoot || options.ArtifactDir != artifactDir || options.Timeout != timeout {
		t.Fatalf("SBOM worker paths = source %q, artifacts %q, timeout %s", options.Dir, options.ArtifactDir, options.Timeout)
	}
	joined := strings.Join(options.Args, " ")
	if !strings.Contains(joined, "--output "+reportPath) || !strings.HasSuffix(joined, sourceRoot) {
		t.Fatalf("SBOM source/report paths were not retained: %s", joined)
	}
}

func TestResolveSBOMOutputPathRejectsTheScannedSource(t *testing.T) {
	sourceRoot := t.TempDir()
	output := filepath.Join(sourceRoot, "sbom.cdx.json")
	if _, err := resolveSBOMOutputPath(output, sourceRoot); err == nil {
		t.Fatal("SBOM output inside the scanned source was accepted")
	}
}

func TestResolveAndWriteSBOMOutputOutsideTheScannedSource(t *testing.T) {
	parent := t.TempDir()
	sourceRoot := filepath.Join(parent, "project")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	wanted := filepath.Join(parent, "sbom.cdx.json")
	resolved, err := resolveSBOMOutputPath(wanted, sourceRoot)
	if err != nil {
		t.Fatalf("resolve sibling SBOM output: %v", err)
	}
	data := []byte(`{"bomFormat":"CycloneDX"}`)
	if err := writeSBOMOutput(resolved, data); err != nil {
		t.Fatalf("write SBOM output: %v", err)
	}
	got, err := os.ReadFile(wanted)
	if err != nil {
		t.Fatalf("read saved SBOM: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("saved SBOM = %q, want %q", got, data)
	}
}

// Every mode of the supply chain scanner builds the command line of its own
// target.
func TestTrivyModeArgs(t *testing.T) {
	config := strings.Join(trivyArgs(trivyModeConfig, "./infra", "/tmp/out.sarif", "", false), " ")
	if !strings.Contains(config, "config --format sarif") {
		t.Errorf("args = %v, want the config command", config)
	}
	if strings.Contains(config, "--scanners") {
		t.Errorf("args = %v, the IaC pass has no scanner selection", config)
	}
	if strings.Contains(config, "--ignore-unfixed") {
		t.Errorf("args = %v, the IaC pass has no unfixed vulnerabilities", config)
	}

	image := strings.Join(trivyArgs(trivyModeImage, "nginx:latest", "/tmp/out.sarif", "", false), " ")
	if !strings.Contains(image, "image --format sarif") {
		t.Errorf("args = %v, want the image command", image)
	}
	if !strings.Contains(image, "nginx:latest") {
		t.Errorf("args = %v, want the image name", image)
	}

	rootfs := strings.Join(trivyArgs(trivyModeRootfs, "/rootfs", "/tmp/out.sarif", "", false), " ")
	if !strings.Contains(rootfs, "rootfs --format sarif") {
		t.Errorf("args = %v, want the rootfs command", rootfs)
	}

	license := strings.Join(trivyArgs(trivyModeLicense, ".", "/tmp/out.sarif", "", false), " ")
	if !strings.Contains(license, "--scanners license") {
		t.Errorf("args = %v, want the license scanner", license)
	}

	// The cluster pass of Trivy has no SARIF writer: it writes JSON.
	cluster := strings.Join(trivyArgs(trivyModeK8sCluster, "kind-kind", "/tmp/out.json", "", false), " ")
	if !strings.Contains(cluster, "k8s --format json") {
		t.Errorf("args = %v, want the k8s command with the json output", cluster)
	}
}

func TestTrivySbomArgs(t *testing.T) {
	args := strings.Join(trivySbomArgs(trivyModeFS, ".", "/tmp/sbom.json"), " ")
	if !strings.Contains(args, "fs --format cyclonedx") {
		t.Errorf("args = %v, want the cyclonedx output", args)
	}
	if !strings.Contains(args, "--output /tmp/sbom.json") {
		t.Errorf("args = %v, want the output file", args)
	}
	if !strings.Contains(args, "--scanners vuln,license") {
		t.Errorf("args = %v, want the license scanner", args)
	}

	image := strings.Join(trivySbomArgs(trivyModeImage, "nginx:latest", "/tmp/sbom.json"), " ")
	if !strings.Contains(image, "image --format cyclonedx") {
		t.Errorf("args = %v, want the image command", image)
	}
}

// The result of a Trivy pass carries the tool of its kind: a dependency, a
// misconfiguration, a secret or a license.
func TestTrivyClassifyAssignsTheSourceTool(t *testing.T) {
	findings := []Finding{
		{SourceTool: "code.deps", Evidence: map[string]any{"ruleTags": []string{"vulnerability", "security", "HIGH"}}},
		{SourceTool: "code.deps", Evidence: map[string]any{"ruleTags": []string{"misconfiguration", "security", "HIGH"}}},
		{SourceTool: "code.deps", Evidence: map[string]any{"ruleTags": []string{"secret", "security", "CRITICAL"}}},
		{SourceTool: "code.deps", Evidence: map[string]any{"ruleTags": []string{"license", "security", "HIGH"}}},
	}
	classified := trivyClassify(findings, trivyModeFS)

	if classified[0].SourceTool != "code.deps" {
		t.Errorf("the vulnerability source tool = %q", classified[0].SourceTool)
	}
	if classified[1].SourceTool != "code.iac" {
		t.Errorf("the misconfiguration source tool = %q, want code.iac", classified[1].SourceTool)
	}
	if classified[2].SourceTool != "code.secrets" {
		t.Errorf("the secret source tool = %q, want code.secrets", classified[2].SourceTool)
	}
	if classified[3].SourceTool != "code.licenses" {
		t.Errorf("the license source tool = %q, want code.licenses", classified[3].SourceTool)
	}
}

// Trivy puts the matched credential in the message of the result: it must
// never reach the backend in clear.
func TestTrivySecretFindingMasksTheCredential(t *testing.T) {
	const secret = "AKIAQWERTYUIOPASDFGH"
	finding := Finding{
		SourceTool: "code.deps",
		RuleID:     "trivy:aws-access-key-id",
		Title:      "Artifact: config.json\nType: json\nSecret AWS Access Key ID\nSeverity: CRITICAL\nMatch: " + secret,
		Severity:   SeverityCritical,
		Evidence: map[string]any{
			"rule":    "aws-access-key-id",
			"file":    "config.json",
			"line":    12,
			"message": "Artifact: config.json\nType: json\nSecret AWS Access Key ID\nSeverity: CRITICAL\nMatch: " + secret,
		},
	}

	masked := trivySecretFinding(finding)
	encoded, err := json.Marshal(masked.ToMap())
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("the finding leaks the credential: %s", encoded)
	}
	if masked.Title != "Hardcoded secret: AWS Access Key ID" {
		t.Errorf("title = %q", masked.Title)
	}
	if masked.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed for a structural credential", masked.Confidence)
	}
	hash, _ := masked.Evidence["secretHash"].(string)
	if len(hash) != 64 {
		t.Errorf("secretHash = %q, want a sha256 digest", hash)
	}
	if !containsString(masked.Tags, "hardcoded-secret") {
		t.Errorf("tags = %v, want the secrets vocabulary", masked.Tags)
	}
}

// A rule that does not come from the builtin set only matches a shape.
func TestTrivySecretConfidencePerRule(t *testing.T) {
	if got := trivySecretConfidence("aws-access-key-id"); got != ConfidenceConfirmed {
		t.Errorf("confidence(aws-access-key-id) = %q, want %q", got, ConfidenceConfirmed)
	}
	if got := trivySecretConfidence("my-custom-rule"); got != ConfidenceProbable {
		t.Errorf("confidence(my-custom-rule) = %q, want %q", got, ConfidenceProbable)
	}
}

// The cluster pass of Trivy has no SARIF writer: its JSON report is parsed
// into the same canonical findings.
func TestParseTrivyJSON(t *testing.T) {
	report := `{
	  "SchemaVersion": 2,
	  "ArtifactName": "kind-kind",
	  "Results": [{
	    "Target": "alpine:3.15 (alpine 3.15.0)",
	    "Class": "os-pkgs",
	    "Type": "alpine",
	    "Vulnerabilities": [{
	      "VulnerabilityID": "CVE-2021-3711",
	      "PkgName": "libssl1.1",
	      "InstalledVersion": "1.1.1k-r0",
	      "FixedVersion": "1.1.1k-r1",
	      "Severity": "MEDIUM",
	      "Title": "openssl: SM2 Decryption Buffer Overflow"
	    }],
	    "Misconfigurations": [{
	      "ID": "AVD-KSV-0001",
	      "Title": "Container should not run as privileged",
	      "Severity": "HIGH",
	      "Message": "The container runs as privileged",
	      "CauseMetadata": { "StartLine": 12, "EndLine": 12 }
	    }],
	    "Secrets": [{
	      "RuleID": "aws-access-key-id",
	      "Title": "AWS Access Key ID",
	      "Severity": "CRITICAL",
	      "StartLine": 7,
	      "Match": "AKIAQWERTYUIOPASDFGH"
	    }],
	    "Licenses": [{
	      "Severity": "HIGH",
	      "Category": "Restricted",
	      "PkgName": "musl-utils",
	      "Name": "GPL-2.0"
	    }]
	  }]
	}`

	findings, err := parseTrivyJSON([]byte(report))
	if err != nil {
		t.Fatalf("parseTrivyJSON failed: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	byTool := map[string]int{}
	for _, f := range findings {
		byTool[f.SourceTool]++
	}
	if byTool["code.deps"] != 1 || byTool["code.iac"] != 1 || byTool["code.secrets"] != 1 || byTool["code.licenses"] != 1 {
		t.Fatalf("the findings were not attributed to their tool: %v", byTool)
	}

	for _, f := range findings {
		encoded, err := json.Marshal(f.ToMap())
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if strings.Contains(string(encoded), "AKIAQWERTYUIOPASDFGH") {
			t.Fatalf("the finding leaks the credential: %s", encoded)
		}
	}
}

// The SBOM of the audited software: the document, the digest of the file and
// its metadata.
func TestTrivySbomDocumentAndMetadata(t *testing.T) {
	document := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
	  "version": 1,
	  "metadata": {
	    "timestamp": "2026-01-02T03:04:05Z",
	    "tools": [{ "vendor": "aquasecurity", "name": "trivy", "version": "0.58.2" }],
	    "component": { "type": "application", "name": "example" }
	  },
	  "components": [
	    { "type": "library", "name": "lodash", "version": "4.17.21" },
	    { "type": "library", "name": "express", "version": "4.18.2" }
	  ]
	}`

	metadata := trivySbomMetadata([]byte(document))
	if metadata["bom_format"] != "CycloneDX" {
		t.Errorf("bom format = %v", metadata["bom_format"])
	}
	if metadata["spec_version"] != "1.6" {
		t.Errorf("spec version = %v", metadata["spec_version"])
	}
	if metadata["timestamp"] != "2026-01-02T03:04:05Z" {
		t.Errorf("timestamp = %v", metadata["timestamp"])
	}
	if metadata["components_count"] != 2 {
		t.Errorf("components count = %v, want 2", metadata["components_count"])
	}
	tools, _ := metadata["tools"].([]map[string]any)
	if len(tools) != 1 || tools[0]["name"] != "trivy" {
		t.Errorf("tools = %v", metadata["tools"])
	}

	parsed := trivySbomDocument([]byte(document))
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("the document was not decoded: %v", parsed)
	}
}

// The SBOM of the audited software: the document, the digest of the file and
// the metadata travel together in the response of the tool.
func TestTrivySbomResponseCarriesTheDocumentAndItsDigest(t *testing.T) {
	document := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "metadata": { "timestamp": "2026-01-02T03:04:05Z", "tools": [{ "vendor": "aquasecurity", "name": "trivy", "version": "0.58.2" }] },
	  "components": [{ "type": "library", "name": "lodash", "version": "4.17.21" }]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("cannot write the sbom: %v", err)
	}
	sum, err := sha256File(path)
	if err != nil {
		t.Fatalf("cannot hash the sbom: %v", err)
	}

	res := trivySbomResponse(path, []byte(document), sum)
	if res["sbom_sha256"] != sum {
		t.Errorf("sbom_sha256 = %v, want %s", res["sbom_sha256"], sum)
	}
	if res["sbom_path"] != path {
		t.Errorf("sbom_path = %v, want %s", res["sbom_path"], path)
	}
	if res["sbom_format"] != "cyclonedx" {
		t.Errorf("sbom_format = %v", res["sbom_format"])
	}
	doc, ok := res["sbom"].(map[string]any)
	if !ok {
		t.Fatalf("sbom = %v, want the decoded document", res["sbom"])
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("the document was not decoded: %v", doc)
	}
	metadata, ok := res["sbom_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("sbom_metadata = %v", res["sbom_metadata"])
	}
	if metadata["timestamp"] != "2026-01-02T03:04:05Z" {
		t.Errorf("timestamp = %v", metadata["timestamp"])
	}
	if summary, _ := res["summary"].(string); !strings.Contains(summary, sum) {
		t.Errorf("summary = %q, want the digest of the file", summary)
	}
}

// The history of a repository holds the secrets that were already deleted
// from the working tree — the finding that matters most in a repository.
func TestGitleaksGitFindsADeletedSecret(t *testing.T) {
	binary, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Skip("gitleaks is not installed in this environment")
	}

	const secret = "AKIAQWERTYUIOPASDFGH"
	repo := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=argos",
			"GIT_AUTHOR_EMAIL=argos@example.test",
			"GIT_COMMITTER_NAME=argos",
			"GIT_COMMITTER_EMAIL=argos@example.test",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	run("init", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "config.js"), []byte("aws_key = \""+secret+"\"\n"), 0o600); err != nil {
		t.Fatalf("cannot write the secret file: %v", err)
	}
	run("add", "config.js")
	run("commit", "-m", "add the configuration")

	// The secret leaves the working tree but stays in the history.
	if err := os.Remove(filepath.Join(repo, "config.js")); err != nil {
		t.Fatalf("cannot remove the secret file: %v", err)
	}
	run("commit", "-am", "drop the configuration")

	report := filepath.Join(t.TempDir(), "gitleaks.json")
	args := gitleaksArgs(gitleaksModeGit, repo, report)
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 1 {
			t.Fatalf("gitleaks git failed: %v\n%s", err, out)
		}
		// Exit code 1 means that gitleaks found a secret.
	}

	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("cannot read the gitleaks report: %v", err)
	}
	findings, err := parseGitleaksJSON(data)
	if err != nil {
		t.Fatalf("parseGitleaksJSON failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("the secret of the history must be reported")
	}

	encoded, err := json.Marshal(findingsToMaps(findings))
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("the report leaks the secret in clear: %s", encoded)
	}
}

func TestBaseResultCodeSecretsExitCode(t *testing.T) {
	// Gitleaks returns 1 when findings are detected
	res := baseResult("code.secrets", "/path/to/repo", &runResult{
		ExitCode: 1,
	})
	if res["status"] != "completed" {
		t.Fatalf("expected status 'completed' for code.secrets with exit code 1, got %v", res["status"])
	}

	// Exit code 2 indicates actual execution error / flag failure
	resErr := baseResult("code.secrets", "/path/to/repo", &runResult{
		ExitCode: 2,
		Stderr:   "fatal: flag provided but not defined",
	})
	if resErr["status"] != "error" {
		t.Fatalf("expected status 'error' for code.secrets with exit code 2, got %v", resErr["status"])
	}

	// Normal tools with exit code 1 are errors
	resGeneric := baseResult("web.probe", "https://example.com", &runResult{
		ExitCode: 1,
	})
	if resGeneric["status"] != "error" {
		t.Fatalf("expected status 'error' for web.probe with exit code 1, got %v", resGeneric["status"])
	}
}
