package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// Gitleaks scan modes.
const (
	gitleaksModeGit  = "git"
	gitleaksModeDir  = "dir"
	gitleaksModeBoth = "both"
)

// Trivy scan modes.
//
// The modes are the targets Trivy knows how to scan, plus the license pass
// that the supply chain audits ask for.
const (
	trivyModeFS          = "fs"
	trivyModeConfig      = "config"
	trivyModeK8s         = "k8s"
	trivyModeK8sCluster  = "k8s-cluster"
	trivyModeImage       = "image"
	trivyModeRootfs      = "rootfs"
	trivyModeLicense     = "license"
	trivyModeAll         = "all"
	trivyModeSBOMDefault = "fs"
)

// trivyUserModes are the modes the code.deps tool accepts.
var trivyUserModes = []string{trivyModeFS, trivyModeConfig, trivyModeK8s, trivyModeImage, trivyModeRootfs, trivyModeAll}

// maxSbomBytes bounds the SBOM document the tool embeds in its response:
// past that size the file and its digest are the deliverable.
const maxSbomBytes = 8 << 20

// trivyAllModes are the passes the "all" mode runs: the dependencies of the
// tree, the infrastructure as code and the licenses.
var trivyAllModes = []string{trivyModeFS, trivyModeConfig, trivyModeLicense}

// semgrepRulePacks is the fixed rule set of code.sast. The previous default
// was `auto`, which resolves to a different rule set on every registry
// update: two runs of the same commit were not comparable and a rule that
// disappeared could not be reproduced. The packs are pinned by name, so the
// scan is reproducible.
//
//	p/security-audit — broad security rules (injection, crypto, SSRF, …)
//	p/owasp-top-ten  — the OWASP Top 10 categories
//	p/cwe-top-25     — the 25 most exploited CWE classes
//	p/trailofbits    — rules audited by Trail of Bits (concurrency, unsafe
//	                   deserialization, taint in ML/Solidity/Python stacks)
var semgrepRulePacks = []string{
	"p/security-audit",
	"p/owasp-top-ten",
	"p/cwe-top-25",
	"p/trailofbits",
}

// gitleaksHighConfidenceRules are the gitleaks rules that match a
// structurally valid credential (fixed prefix, checksum, key format). A hit
// on one of them is a real credential; the generic rules only match a shape
// and stay "probable".
var gitleaksHighConfidenceRules = map[string]bool{
	"aws-access-token":           true,
	"alibaba-access-key-id":      true,
	"alibaba-secret-key":         true,
	"azure-ad-client-secret":     true,
	"bitbucket-app-password":     true,
	"datadog-access-token":       true,
	"digitalocean-access-token":  true,
	"digitalocean-pat":           true,
	"discord-api-token":          true,
	"doppler-api-token":          true,
	"duffel-api-token":           true,
	"dynatrace-api-token":        true,
	"easypost-api-token":         true,
	"etsy-access-token":          true,
	"facebook-secret":            true,
	"fastly-api-token":           true,
	"finicity-api-token":         true,
	"flickr-access-token":        true,
	"frameio-api-token":          true,
	"gcp-api-key":                true,
	"gcp-service-account":        true,
	"gitlab-pat":                 true,
	"gitlab-ptt":                 true,
	"gitlab-rrt":                 true,
	"github-app-token":           true,
	"github-fine-grained-pat":    true,
	"github-oauth":               true,
	"github-pat":                 true,
	"github-refresh-token":       true,
	"hashicorp-tf-api-token":     true,
	"hubspot-api-token":          true,
	"huggingface-access-token":   true,
	"intercom-api-token":         true,
	"jwt":                        true,
	"linear-api-token":           true,
	"linkedin-client-secret":     true,
	"lob-api-key":                true,
	"mapbox-api-token":           true,
	"netscaler-password":         true,
	"new-relic-user-api-key":     true,
	"npm-access-token":           true,
	"nytimes-access-token":       true,
	"okta-access-token":          true,
	"openai-api-key":             true,
	"planetscale-access-token":   true,
	"planetscale-password":       true,
	"postman-api-token":          true,
	"private-key":                true,
	"pypi-upload-token":          true,
	"rubygems-api-token":         true,
	"sendgrid-api-token":         true,
	"sidekiq-secret":             true,
	"slack-app-token":            true,
	"slack-bot-token":            true,
	"slack-config-access-token":  true,
	"slack-config-refresh-token": true,
	"slack-user-token":           true,
	"snyk-api-token":             true,
	"square-access-token":        true,
	"stripe-access-token":        true,
	"telegram-bot-api-token":     true,
	"twilio-api-key":             true,
	"typeform-api-token":         true,
}

// trivyHighConfidenceRules are the Trivy secret rules that match a
// structurally valid credential (fixed prefix, checksum, key format).
//
// The criterion is the same the gitleaks pass uses: a hit on one of these
// rules is a real credential and the finding is "confirmed"; a rule that
// comes from a custom secret configuration only matches a shape and stays
// "probable".
var trivyHighConfidenceRules = map[string]bool{
	"adobe-client-id": true, "adobe-client-secret": true,
	"age-secret-key": true, "alibaba-access-key-id": true, "alibaba-secret-key": true,
	"asana-client-id": true, "asana-client-secret": true, "atlassian-api-token": true,
	"aws-access-key-id": true, "aws-secret-access-key": true,
	"beamer-api-token": true, "bitbucket-client-id": true, "bitbucket-client-secret": true,
	"clojars-api-token": true, "contentful-delivery-api-token": true,
	"databricks-api-token": true, "discord-api-token": true, "discord-client-id": true,
	"discord-client-secret": true, "dockerconfig-secret": true, "doppler-api-token": true,
	"dropbox-api-secret": true, "dropbox-long-lived-api-token": true, "dropbox-short-lived-api-token": true,
	"duffel-api-token": true, "dynatrace-api-token": true, "easypost-api-token": true,
	"facebook-token": true, "fastly-api-token": true, "finicity-api-token": true,
	"finicity-client-secret": true, "flutterwave-enc-key": true, "flutterwave-public-key": true,
	"frameio-api-token": true, "gcp-service-account": true, "github-app-token": true,
	"github-fine-grained-pat": true, "github-oauth": true, "github-pat": true,
	"github-refresh-token": true, "gitlab-pat": true, "gocardless-api-token": true,
	"grafana-api-token": true, "hashicorp-tf-api-token": true, "heroku-api-key": true,
	"hugging-face-access-token": true, "hubspot-api-token": true, "intercom-api-token": true,
	"intercom-client-secret": true, "ionic-api-token": true, "jwt-token": true,
	"linear-api-token": true, "linear-client-secret": true, "linkedin-client-id": true,
	"linkedin-client-secret": true, "lob-api-key": true, "lob-pub-api-key": true,
	"mailchimp-api-key": true, "mailgun-signing-key": true, "mailgun-token": true,
	"mapbox-api-token": true, "messagebird-api-token": true, "messagebird-client-id": true,
	"new-relic-browser-api-token": true, "new-relic-user-api-id": true, "new-relic-user-api-key": true,
	"npm-access-token": true, "planetscale-api-token": true, "planetscale-password": true,
	"postman-api-token": true, "private-key": true, "private-packagist-token": true,
	"pypi-upload-token": true, "rubygems-api-token": true, "sendgrid-api-token": true,
	"sendinblue-api-token": true, "shippo-api-token": true, "shopify-token": true,
	"slack-access-token": true, "slack-web-hook": true, "stripe-publishable-token": true,
	"stripe-secret-token": true, "twilio-api-key": true, "twitch-api-token": true,
	"twitter-token": true, "typeform-api-token": true,
}

type GitleaksEntry struct {
	RuleID      string  `json:"RuleID"`
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	Secret      string  `json:"Secret"`
	Match       string  `json:"Match"`
	Commit      string  `json:"Commit"`
	Author      string  `json:"Author"`
	Email       string  `json:"Email"`
	Date        string  `json:"Date"`
	Entropy     float64 `json:"Entropy"`
	Fingerprint string  `json:"Fingerprint"`
}

// parseGitleaksJSON normalizes the gitleaks report into canonical findings.
func parseGitleaksJSON(data []byte) ([]Finding, error) {
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "[") {
		return nil, fmt.Errorf("decode gitleaks report: expected a JSON array")
	}
	var entries []GitleaksEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode gitleaks report: %w", err)
	}

	var findings []Finding
	for _, e := range entries {
		findings = append(findings, gitleaksFinding(e))
	}
	return findings, nil
}

// gitleaksFinding builds the finding of a gitleaks hit.
//
// The secret never travels in clear: gitleaks runs with --redact and this is
// the second gate for a report produced by another runner — only a masked
// prefix and a one-way digest of the value reach the backend.
func gitleaksFinding(e GitleaksEntry) Finding {
	title := fmt.Sprintf("Hardcoded secret: %s", e.Description)
	if e.Description == "" {
		title = fmt.Sprintf("Hardcoded secret (%s)", e.RuleID)
	}

	evidence := map[string]any{
		"rule":   e.RuleID,
		"file":   e.File,
		"line":   e.StartLine,
		"secret": maskSecret(e.Secret),
	}
	if hash := secretHash(e.Secret); hash != "" {
		evidence["secretHash"] = hash
	}
	if e.Fingerprint != "" {
		evidence["fingerprint"] = e.Fingerprint
	}
	if e.Commit != "" {
		evidence["commit"] = e.Commit
	}
	if e.Entropy > 0 {
		evidence["entropy"] = e.Entropy
	}
	if match := maskMatch(e.Match, e.Secret); match != "" {
		evidence["match"] = match
	}

	return Finding{
		Source:     "code.secrets",
		SourceTool: "code.secrets",
		RuleID:     "gitleaks:" + e.RuleID,
		Title:      title,
		Severity:   SeverityCritical,
		Confidence: gitleaksConfidence(e.RuleID),
		Target:     e.File,
		Vector:     sarifVector(e.File, e.StartLine),
		Evidence:   evidence,
		Tags:       gitleaksTags(e.RuleID, e.File),
	}
}

// maskSecret keeps a recognizable prefix of the secret and never the value:
// "AKIA...WXYZ". Short values are masked completely.
//
// Gitleaks runs with --redact, so the report it writes carries the
// placeholder "REDACTED" instead of the credential: the mask of a redacted
// report is "***" and the hash identifies the placeholder, not the secret.
// The stable identity of the finding is the gitleaks fingerprint (commit,
// file, rule and line), which travels in the evidence untouched.
func maskSecret(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return ""
	}
	if strings.EqualFold(trimmed, "REDACTED") {
		return "***"
	}
	runes := []rune(trimmed)
	if len(runes) <= 8 {
		return "***"
	}
	return string(runes[:4]) + "..." + string(runes[len(runes)-4:])
}

// maskMatch keeps the surrounding context of a match with the secret
// replaced by its masked form. When the secret is not part of the match the
// match is dropped: it could carry another secret.
func maskMatch(match, secret string) string {
	if match == "" || secret == "" {
		return ""
	}
	if !strings.Contains(match, secret) {
		return ""
	}
	return strings.ReplaceAll(match, secret, maskSecret(secret))
}

// secretHash is the one-way digest of the detected value: it identifies the
// same secret across runs without revealing it.
func secretHash(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}

// gitleaksConfidence decides how much a gitleaks hit can be trusted.
func gitleaksConfidence(ruleID string) string {
	if gitleaksHighConfidenceRules[strings.ToLower(strings.TrimSpace(ruleID))] {
		return ConfidenceConfirmed
	}
	return ConfidenceProbable
}

// gitleaksTags maps a gitleaks rule onto the canonical secrets vocabulary.
func gitleaksTags(ruleID, file string) []string {
	tags := []string{"secret-exposure", "hardcoded-secret"}
	lower := strings.ToLower(ruleID)
	switch {
	case strings.Contains(lower, "aws"):
		tags = append(tags, "aws-access-key")
	case strings.Contains(lower, "api-key"):
		tags = append(tags, "api-key")
	case strings.Contains(lower, "token"):
		tags = append(tags, "token")
	case strings.Contains(lower, "password"), strings.Contains(lower, "private-key"):
		tags = append(tags, "credentials")
	}
	if strings.Contains(strings.ToLower(file), ".env") {
		tags = append(tags, ".env")
	}
	return dedupeTags(tags)
}

// gitleaksArgs builds the command line of a gitleaks run. --redact is not
// optional: the report is the only channel through which the secret would
// reach the backend.
func gitleaksArgs(mode, path, reportPath string) []string {
	return []string{
		mode,
		path,
		"--report-format", "json",
		"--report-path", reportPath,
		"--redact",
		"--no-banner",
	}
}

func gitleaksRunOptions(mode, sourceRoot, reportPath string, timeout time.Duration) runOptions {
	return runOptions{
		Args:        gitleaksArgs(mode, sourceRoot, reportPath),
		Timeout:     timeout,
		Dir:         sourceRoot,
		ArtifactDir: filepath.Dir(reportPath),
	}
}

// semgrepArgs builds the command line of a semgrep run.
//
// --metrics=off keeps the scanned code out of the telemetry backend and
// --dataflow-traces asks for the taint chain of every hit: the chain is the
// evidence that explains why the rule matched.
func semgrepArgs(rules string, target, output string) []string {
	args := []string{"scan", "--sarif", "--output", output}
	if rules != "" {
		args = append(args, "--config", rules)
	} else {
		for _, pack := range semgrepRulePacks {
			args = append(args, "--config", pack)
		}
	}
	args = append(args, "--metrics=off", "--dataflow-traces")
	return append(args, target)
}

// trivyArgs builds the command line of a trivy run.
//
// Every mode but the cluster one writes SARIF: `trivy k8s` has no SARIF
// writer, so the cluster pass writes JSON and is parsed apart.
func trivyArgs(mode, target, output, severity string, ignoreUnfixed bool) []string {
	switch mode {
	case trivyModeConfig:
		// the IaC pass has no scanner selection: misconfiguration is the
		// only thing it knows how to do.
		args := []string{"config", "--format", "sarif", "--output", output}
		if severity != "" {
			args = append(args, "--severity", severity)
		}
		return append(args, target)
	case trivyModeK8sCluster:
		args := []string{"k8s", "--format", "json", "--output", output}
		if severity != "" {
			args = append(args, "--severity", severity)
		}
		return append(args, target)
	default:
		scanners := "vuln,secret,misconfig"
		if mode == trivyModeLicense {
			scanners = "license"
		}
		args := []string{mode, "--format", "sarif", "--output", output, "--scanners", scanners}
		if severity != "" {
			args = append(args, "--severity", severity)
		}
		if ignoreUnfixed {
			args = append(args, "--ignore-unfixed")
		}
		return append(args, target)
	}
}

// trivySbomArgs builds the command line of a CycloneDX SBOM generation.
//
// The license scanner runs with it: an SBOM without the licenses of the
// packages is half of what the compliance frameworks ask for.
func trivySbomArgs(mode, target, output string) []string {
	return []string{
		mode,
		"--format", "cyclonedx",
		"--output", output,
		"--scanners", "vuln,license",
		target,
	}
}

func trivySbomRunOptions(mode, target, sourceRoot, output string, timeout time.Duration) runOptions {
	return runOptions{
		Args:        trivySbomArgs(mode, target, output),
		Timeout:     timeout,
		Dir:         sourceRoot,
		ArtifactDir: filepath.Dir(output),
	}
}

func resolveSBOMOutputPath(output, sourceRoot string) (string, error) {
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return "", fmt.Errorf("resolve SBOM output path: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absOutput))
	if err != nil {
		return "", fmt.Errorf("resolve SBOM output directory: %w", err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		if err != nil {
			return "", fmt.Errorf("SBOM output directory is unavailable: %w", err)
		}
		return "", fmt.Errorf("SBOM output parent is not a directory")
	}
	resolvedOutput := filepath.Join(parent, filepath.Base(absOutput))
	if info, statErr := os.Lstat(resolvedOutput); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("SBOM output must be a regular file, not a symlink or special file")
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect SBOM output: %w", statErr)
	}
	resolvedSource, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return "", fmt.Errorf("resolve scanned source directory: %w", err)
	}
	if pathsOverlapLocal(resolvedSource, resolvedOutput) {
		return "", fmt.Errorf("SBOM output must be outside the read-only scanned source")
	}
	return resolvedOutput, nil
}

func pathsOverlapLocal(left, right string) bool {
	contains := func(parent, candidate string) bool {
		relative, err := filepath.Rel(parent, candidate)
		return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
	}
	return contains(left, right) || contains(right, left)
}

func writeSBOMOutput(destination string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".argos-sbom-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary SBOM output: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write SBOM output: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync SBOM output: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close SBOM output: %w", err)
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("publish SBOM output: %w", err)
	}
	return nil
}

// gitleaksRelativePath normalizes a reported path so the working tree and
// the history of the same repository produce the same deduplication key.
func gitleaksRelativePath(file, root string) string {
	if file == "" {
		return ""
	}
	if root == "" || !filepath.IsAbs(file) {
		return filepath.ToSlash(file)
	}
	rel, err := filepath.Rel(root, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(file)
	}
	return filepath.ToSlash(rel)
}

// gitleaksMerge deduplicates the findings of the two scan modes: the same
// secret in the working tree and in the history of the repository is one
// finding, not two.
func gitleaksMerge(root string, groups ...[]Finding) []Finding {
	var out []Finding
	index := map[string]int{}
	for _, group := range groups {
		for _, f := range group {
			key := gitleaksDedupKey(root, f)
			if pos, ok := index[key]; ok {
				out[pos] = gitleaksMergeFinding(out[pos], f)
				continue
			}
			index[key] = len(out)
			out = append(out, f)
		}
	}
	return out
}

// gitleaksDedupKey identifies a finding by file, line and rule.
func gitleaksDedupKey(root string, f Finding) string {
	line := 0
	if value, ok := f.Evidence["line"].(int); ok {
		line = value
	}
	rule, _ := f.Evidence["rule"].(string)
	return fmt.Sprintf("%s|%d|%s", gitleaksRelativePath(f.Target, root), line, rule)
}

// gitleaksMergeFinding completes the evidence of a finding with the keys the
// other mode found (the history run knows the commit, the working tree run
// knows the absolute path).
func gitleaksMergeFinding(base, extra Finding) Finding {
	for key, value := range extra.Evidence {
		if _, ok := base.Evidence[key]; !ok {
			base.Evidence[key] = value
		}
	}
	return base
}

func RegisterCodeScan(s *mcp.Server, env *Env) {
	// code.sast (Semgrep)
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "code.sast",
			Description: "Static application security testing (SAST) on repository source code powered by Semgrep with SARIF normalization.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":    {Type: "string", Description: "Target directory or file path to analyze (default '.')"},
					"rules":   {Type: "string", Description: "Semgrep rule pack or config (default: p/security-audit, p/owasp-top-ten, p/cwe-top-25, p/trailofbits)"},
					"timeout": {Type: "integer", Description: "Timeout in seconds (default 180, max 300)"},
				},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Path    string `json:"path"`
				Rules   string `json:"rules"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			targetPath := input.Path
			if targetPath == "" {
				targetPath = "."
			}
			rules := strings.TrimSpace(input.Rules)

			timeout := clampTimeout(input.Timeout, 180)
			fs, r, installed := runSemgrep(toolContext(ctx), env, targetPath, rules, timeout)

			fs, truncated := capFindings(fs)
			res := baseResult("code.sast", targetPath, r)
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			if r.ExitCode == 0 {
				res["summary"] = fmt.Sprintf("%d SAST findings detected", len(fs))
			} else {
				res["summary"] = "SAST scan incomplete; no complete report was available"
			}
			res["rule_packs"] = semgrepPacks(rules)
			if installed {
				res["installed"] = "semgrep " + env.Spec("semgrep").Version
			}
			return res, nil
		},
	)

	// code.deps (Trivy)
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "code.deps",
			Description: "Supply chain scanner for repository dependencies, infrastructure as code, hardcoded secrets, " +
				"licenses and root filesystems, using Trivy with SARIF output. Container image and live Kubernetes scans " +
				"are currently unavailable in the isolated worker because scoped image and cluster inputs are not implemented.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":           {Type: "string", Description: "Path to project directory, lockfile or root filesystem (default '.'); image and live cluster inputs are currently unavailable"},
					"mode":           {Type: "string", Description: "Scan mode: 'fs' (default), 'config' (IaC), 'rootfs' or 'all' (fs + config + licenses); 'k8s' scans a local manifest path as IaC, while live clusters and 'image' return unavailable until scoped inputs are supported"},
					"severity":       {Type: "string", Description: "Comma separated severities to report (e.g. 'CRITICAL,HIGH'); empty reports every severity"},
					"ignore_unfixed": {Type: "boolean", Description: "Skip the vulnerabilities without a published fix (default false)"},
					"timeout":        {Type: "integer", Description: "Timeout in seconds (default 180, max 300)"},
				},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Path          string `json:"path"`
				Mode          string `json:"mode"`
				Severity      string `json:"severity"`
				IgnoreUnfixed bool   `json:"ignore_unfixed"`
				Timeout       int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			targetPath := input.Path
			if targetPath == "" {
				targetPath = "."
			}
			mode := strings.ToLower(strings.TrimSpace(input.Mode))
			if mode == "" {
				mode = trivyModeFS
			}
			if !containsString(trivyUserModes, mode) {
				return nil, invalidParams(fmt.Errorf("mode must be one of %s", strings.Join(trivyUserModes, ", ")))
			}

			timeout := clampTimeout(input.Timeout, 180)
			bin, installed, e := env.Binary(toolContext(ctx), "trivy")
			if e != nil {
				return nil, e
			}

			modes := []string{mode}
			if mode == trivyModeAll {
				modes = trivyAllModes
			}
			if mode == trivyModeK8s {
				// A path is a set of manifests: the IaC pass is the one
				// that reads them. Anything else is the name of a
				// kubeconfig context: the cluster pass is the one that
				// knows how to reach it.
				modes = []string{trivyModeK8sCluster}
				if _, err := os.Stat(targetPath); err == nil {
					modes = []string{trivyModeConfig}
				}
			}

			var findings []Finding
			var primary *runResult
			var failures []*runResult
			for _, scanMode := range modes {
				passFindings, r := trivyScan(toolContext(ctx), bin, scanMode, targetPath, input.Severity, input.IgnoreUnfixed, timeout)
				findings = append(findings, passFindings...)
				if r != nil {
					if r.ExitCode != 0 {
						failures = append(failures, r)
					} else if primary == nil {
						primary = r
					}
				}
			}
			if primary == nil && len(failures) > 0 {
				primary = failures[0]
			}
			if primary == nil {
				primary = &runResult{}
			}

			findings, truncated := capFindings(findings)
			res := baseResult("code.deps", targetPath, primary)
			if len(failures) > 0 {
				if primary.ExitCode != 0 {
					res["status"] = "error"
				} else {
					res["status"] = "partial"
				}
			}
			res["complete"] = len(failures) == 0
			res["mode"] = mode
			res["modes"] = modes
			env.publishFindings(res, findings)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d supply chain findings detected", len(findings))
			var warnings []string
			for _, failure := range failures {
				message := strings.TrimSpace(failure.Stderr)
				if message == "" {
					message = fmt.Sprintf("exit code %d", failure.ExitCode)
				}
				warnings = append(warnings, message)
			}
			if len(warnings) > 0 {
				res["warnings"] = warnings
				res["summary"] = fmt.Sprintf("%s; scan incomplete for one or more modes", res["summary"])
			}
			if installed {
				res["installed"] = "trivy " + env.Spec("trivy").Version
			}
			return res, nil
		},
	)

	// code.sbom (Trivy CycloneDX)
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "code.sbom",
			Description: "Generates the CycloneDX SBOM of an audited repository or filesystem with Trivy. Container image " +
				"SBOM generation is currently unavailable in the isolated worker until scoped image input is supported. " +
				"Returns the SBOM document, the sha256 of the file and its metadata. This is the SBOM of the target, " +
				"not the one of the auditor.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":    {Type: "string", Description: "Path to the audited project or filesystem (default '.')"},
					"mode":    {Type: "string", Description: "SBOM target: 'fs' (default); 'image' currently returns an unavailable status"},
					"output":  {Type: "string", Description: "Where to write the SBOM file; the parent directory must exist and the file must be outside the scanned source (default: a retained temporary artifact)"},
					"timeout": {Type: "integer", Description: "Timeout in seconds (default 300, max 300)"},
				},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Path    string `json:"path"`
				Mode    string `json:"mode"`
				Output  string `json:"output"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			targetPath := input.Path
			if targetPath == "" {
				targetPath = "."
			}
			mode := strings.ToLower(strings.TrimSpace(input.Mode))
			if mode == "" {
				mode = trivyModeSBOMDefault
			}
			if mode != trivyModeSBOMDefault && mode != trivyModeImage {
				return nil, invalidParams(fmt.Errorf("mode must be %q or %q", trivyModeSBOMDefault, trivyModeImage))
			}

			timeout := clampTimeout(input.Timeout, 300)
			bin, installed, e := env.Binary(toolContext(ctx), "trivy")
			if e != nil {
				return nil, e
			}
			if mode == trivyModeImage {
				r := &runResult{ExitCode: -1, Stderr: "container image SBOM generation is unavailable in the isolated worker until an image archive or scoped registry input is provided"}
				res := baseResult("code.sbom", targetPath, r)
				res["summary"] = r.Stderr
				return res, nil
			}

			targetPath, err := filepath.Abs(targetPath)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "cannot resolve the scanned path: " + err.Error()}
			}
			targetInfo, err := os.Stat(targetPath)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "scanned path is unavailable: " + err.Error()}
			}
			sourceRoot := targetPath
			if !targetInfo.IsDir() {
				sourceRoot = filepath.Dir(targetPath)
			}
			requestedOutput := strings.TrimSpace(input.Output)
			sbomPath := ""
			if requestedOutput != "" {
				sbomPath, err = resolveSBOMOutputPath(requestedOutput, sourceRoot)
				if err != nil {
					return nil, invalidParams(err)
				}
			}
			artifactDir, err := os.MkdirTemp("", "argos-sbom-artifacts-")
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "failed to create SBOM artifact directory: " + err.Error()}
			}
			if pathsOverlapLocal(sourceRoot, artifactDir) {
				os.RemoveAll(artifactDir)
				return nil, &mcp.ErrorObj{Code: -32603, Message: "temporary SBOM artifacts must be outside the read-only scanned source; configure the system temporary directory outside the project"}
			}
			keepArtifactDir := false
			defer func() {
				if !keepArtifactDir {
					os.RemoveAll(artifactDir)
				}
			}()

			artifactPath := filepath.Join(artifactDir, "sbom.cdx.json")
			if requestedOutput == "" {
				sbomPath = artifactPath
			}

			r := run(toolContext(ctx), bin, trivySbomRunOptions(mode, targetPath, sourceRoot, artifactPath, time.Duration(timeout)*time.Second))
			if r.ExitCode != 0 {
				res := baseResult("code.sbom", targetPath, r)
				res["summary"] = "the SBOM generation did not complete successfully"
				return res, nil
			}

			data, err := os.ReadFile(artifactPath)
			if err != nil || len(data) == 0 {
				reason := "Trivy did not return an SBOM report"
				if err != nil {
					reason += ": " + err.Error()
				}
				markRunIncomplete(r, reason)
				res := baseResult("code.sbom", targetPath, r)
				res["status"] = "error"
				res["summary"] = "the SBOM could not be generated"
				return res, nil
			}
			sum, err := sha256File(artifactPath)
			if err != nil {
				markRunIncomplete(r, "cannot hash the generated SBOM: "+err.Error())
				res := baseResult("code.sbom", targetPath, r)
				res["status"] = "error"
				res["summary"] = "the generated SBOM could not be verified"
				return res, nil
			}
			if requestedOutput != "" {
				if err := writeSBOMOutput(sbomPath, data); err != nil {
					markRunIncomplete(r, "cannot save the requested SBOM output: "+err.Error())
					res := baseResult("code.sbom", targetPath, r)
					res["status"] = "error"
					res["summary"] = "the generated SBOM could not be saved to the requested output"
					return res, nil
				}
			} else {
				keepArtifactDir = true
			}

			res := baseResult("code.sbom", targetPath, r)
			for key, value := range trivySbomResponse(sbomPath, data, sum) {
				res[key] = value
			}
			if installed {
				res["installed"] = "trivy " + env.Spec("trivy").Version
			}
			return res, nil
		},
	)

	// code.secrets (Gitleaks)
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "code.secrets",
			Description: "Deterministic secret and token leak detection across a repository and its git history using Gitleaks.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":    {Type: "string", Description: "Path to repository or folder to scan (default '.')"},
					"mode":    {Type: "string", Description: "Scan mode: 'git' (history only), 'dir' (working tree only) or 'both' (default 'both')"},
					"timeout": {Type: "integer", Description: "Timeout in seconds (default 120, max 300)"},
				},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Path    string `json:"path"`
				Mode    string `json:"mode"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			targetPath := input.Path
			if targetPath == "" {
				targetPath = "."
			}
			mode := strings.ToLower(strings.TrimSpace(input.Mode))
			switch mode {
			case gitleaksModeGit, gitleaksModeDir, gitleaksModeBoth:
			case "":
				mode = gitleaksModeBoth
			default:
				return nil, invalidParams(fmt.Errorf("mode must be %q, %q or %q", gitleaksModeGit, gitleaksModeDir, gitleaksModeBoth))
			}

			timeout := clampTimeout(input.Timeout, 120)
			bin, installed, e := env.Binary(toolContext(ctx), "gitleaks")
			if e != nil {
				return nil, e
			}

			absPath, _ := filepath.Abs(targetPath)
			modes := []string{mode}
			if mode == gitleaksModeBoth {
				modes = []string{gitleaksModeGit, gitleaksModeDir}
			}
			artifactDir, err := os.MkdirTemp("", "argos-gitleaks-artifacts-")
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "failed to create private artifact directory: " + err.Error()}
			}
			defer os.RemoveAll(artifactDir)

			var groups [][]Finding
			var success *runResult
			var failures []*runResult
			for _, scanMode := range modes {
				tmpJSON, err := os.CreateTemp(artifactDir, "gitleaks-*.json")
				if err != nil {
					return nil, &mcp.ErrorObj{Code: -32603, Message: "failed to create temp file: " + err.Error()}
				}
				tmpPath := tmpJSON.Name()
				tmpJSON.Close()

				r := run(toolContext(ctx), bin, gitleaksRunOptions(scanMode, absPath, tmpPath, time.Duration(timeout)*time.Second))

				var fs []Finding
				reportValid := false
				data, reportErr := os.ReadFile(tmpPath)
				if reportErr == nil && len(data) > 0 {
					fs, reportErr = parseGitleaksJSON(data)
					reportValid = reportErr == nil
				}
				if !reportValid {
					reason := "Gitleaks returned no valid report"
					if reportErr != nil {
						reason += ": " + reportErr.Error()
					}
					markRunIncomplete(r, reason)
				}
				os.Remove(tmpPath)

				groups = append(groups, fs)
				if gitleaksRunFailed(r, reportValid) {
					failures = append(failures, r)
				} else if success == nil {
					success = r
				}
			}

			fs := gitleaksMerge(absPath, groups...)
			fs, truncated := capFindings(fs)

			primary := success
			if primary == nil && len(failures) > 0 {
				primary = failures[0]
			}
			if primary == nil {
				primary = &runResult{}
			}
			res := baseResult("code.secrets", targetPath, primary)
			if success == nil {
				// Every mode failed: the scan did not happen.
				res["status"] = "error"
			} else if len(failures) > 0 {
				res["status"] = "partial"
			}
			res["mode"] = mode
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			if success != nil {
				res["summary"] = fmt.Sprintf("%d secrets detected", len(fs))
				if len(failures) > 0 {
					res["summary"] = fmt.Sprintf("%s; scan incomplete for one or more modes", res["summary"])
				}
			} else {
				res["summary"] = "secret scan incomplete; no valid report was available"
			}
			if len(failures) > 0 {
				res["complete"] = false
			} else {
				res["complete"] = success != nil
			}
			var warnings []string
			for _, failure := range failures {
				message := strings.TrimSpace(failure.Stderr)
				if message == "" {
					message = fmt.Sprintf("exit code %d", failure.ExitCode)
				}
				warnings = append(warnings, message)
			}
			if len(warnings) > 0 {
				res["warnings"] = warnings
			}
			if installed {
				res["installed"] = "gitleaks " + env.Spec("gitleaks").Version
			}
			return res, nil
		},
	)

	// The semantic analysis tools live in codeql.go: they are registered
	// from here so the code tools of the server stay in one place.
	RegisterCodeQL(s, env)
}

// trivyScan runs one trivy pass and normalizes its findings.
//
// The result of a pass carries the source tool of the kind of result it
// holds: a dependency, a misconfiguration, a secret or a license.
func trivyScan(ctx context.Context, bin, mode, target, severity string, ignoreUnfixed bool, timeout int) ([]Finding, *runResult) {
	if mode == trivyModeK8sCluster {
		return nil, &runResult{ExitCode: -1, Stderr: "Kubernetes cluster scans are unavailable in the isolated worker until kubeconfig and cluster traffic use the scoped gateway"}
	}
	if mode == trivyModeImage {
		return nil, &runResult{ExitCode: -1, Stderr: "container image scans are unavailable in the isolated worker until an image archive or scoped registry input is provided"}
	}
	targetPath, err := filepath.Abs(target)
	if err != nil {
		return nil, &runResult{ExitCode: -1, Stderr: err.Error()}
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		return nil, &runResult{ExitCode: -1, Stderr: fmt.Sprintf("Trivy source %q is unavailable: %v", target, err)}
	}
	sourceRoot := targetPath
	if !targetInfo.IsDir() {
		sourceRoot = filepath.Dir(targetPath)
	}
	artifactDir, err := os.MkdirTemp("", "argos-trivy-artifacts-")
	if err != nil {
		return nil, &runResult{ExitCode: -1, Stderr: err.Error()}
	}
	defer os.RemoveAll(artifactDir)
	output, err := os.CreateTemp(artifactDir, "trivy-*.report")
	if err != nil {
		return nil, &runResult{ExitCode: -1, Stderr: err.Error()}
	}
	outputPath := output.Name()
	output.Close()
	defer os.Remove(outputPath)

	args := trivyArgs(mode, targetPath, outputPath, severity, ignoreUnfixed)
	r := run(ctx, bin, runOptions{
		Args:        args,
		Timeout:     time.Duration(timeout) * time.Second,
		Dir:         sourceRoot,
		ArtifactDir: artifactDir,
	})

	data, err := os.ReadFile(outputPath)
	if err != nil || len(data) == 0 {
		reason := "Trivy returned no SARIF report"
		if err != nil {
			reason += ": " + err.Error()
		}
		markRunIncomplete(r, reason)
		return nil, r
	}

	var findings []Finding
	if mode == trivyModeK8sCluster {
		findings, err = parseTrivyJSON(data)
		if err != nil {
			return nil, r
		}
	} else {
		// The shared SARIF parser assumes the Semgrep engine when it
		// prefixes the rules: Trivy is not that engine, so the prefix is
		// rewritten below.
		findings, err = parseSarifReport(data, "code.deps")
		if err != nil {
			markRunIncomplete(r, "Trivy returned an invalid SARIF report: "+err.Error())
			return nil, r
		}
	}
	return trivyClassify(findings, mode), r
}

// trivyClassify assigns the source tool of every result and masks the
// secrets.
func trivyClassify(findings []Finding, mode string) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		class := trivyResultClass(f)
		if class == "secret" {
			f = trivySecretFinding(f)
		}
		sourceTool := trivySourceTool(class, mode)
		f.Source = sourceTool
		f.SourceTool = sourceTool
		f.Tags = trivyResultTags(f, class, sourceTool)
		out = append(out, f)
	}
	return out
}

// trivyResultClass reads the kind of a Trivy result out of the tags its
// SARIF rule carries ("vulnerability", "misconfiguration", "secret",
// "license").
func trivyResultClass(f Finding) string {
	tags, _ := f.Evidence["ruleTags"].([]string)
	if len(tags) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(tags[0]))
}

// trivySourceTool maps the kind of a result onto the tool that owns it.
func trivySourceTool(class, mode string) string {
	switch class {
	case "secret":
		return "code.secrets"
	case "misconfiguration":
		return "code.iac"
	case "license":
		return "code.licenses"
	}
	switch mode {
	case trivyModeImage:
		return "code.image"
	case trivyModeConfig, trivyModeK8s, trivyModeK8sCluster:
		return "code.iac"
	}
	return "code.deps"
}

// trivyResultTags gives every kind of result the tags of its vocabulary.
func trivyResultTags(f Finding, class, sourceTool string) []string {
	tags := f.Tags
	switch class {
	case "secret":
		tags = append(tags, "secret-exposure", "hardcoded-secret")
	case "misconfiguration":
		tags = append(tags, "misconfiguration", "iac")
	case "license":
		tags = append(tags, "license", "supply-chain")
	default:
		tags = append(tags, "dependency", "supply-chain")
	}
	if sourceTool == "code.image" {
		tags = append(tags, "container-image")
	}
	return dedupeTags(tags)
}

// trivySecretFinding rewrites a Trivy secret result so the matched
// credential never reaches the backend.
//
// Trivy puts the raw match in the message of the result: the finding keeps
// the shape of the credential (a masked prefix and suffix) and a one-way
// digest of the value, never the value.
func trivySecretFinding(f Finding) Finding {
	message, _ := f.Evidence["message"].(string)
	secret := trivySecretFromMessage(message)
	rule, _ := f.Evidence["rule"].(string)

	title := trivySecretTitle(message)
	if title == "" {
		title = rule
	}
	if title == "" {
		title = "credential"
	}
	f.Title = "Hardcoded secret: " + title
	f.Severity = SeverityCritical
	f.Confidence = trivySecretConfidence(rule)
	f.Evidence["message"] = trivyRedactedMessage(message, secret)
	f.Evidence["secret"] = maskSecret(secret)
	if hash := secretHash(secret); hash != "" {
		f.Evidence["secretHash"] = hash
	}
	f.Evidence["match"] = maskSecret(secret)
	f.Tags = dedupeTags(append(f.Tags, "secret-exposure", "hardcoded-secret"))
	return f
}

// trivySecretConfidence decides how much a Trivy secret hit can be trusted:
// the same criterion the gitleaks pass uses.
func trivySecretConfidence(ruleID string) string {
	if trivyHighConfidenceRules[strings.ToLower(strings.TrimSpace(ruleID))] {
		return ConfidenceConfirmed
	}
	return ConfidenceProbable
}

// trivySecretFromMessage extracts the matched credential out of the message
// of a Trivy secret result.
func trivySecretFromMessage(message string) string {
	const marker = "Match: "
	idx := strings.LastIndex(message, marker)
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(message[idx+len(marker):])
}

// trivySecretTitle extracts the description of the secret out of the message
// of a Trivy secret result.
func trivySecretTitle(message string) string {
	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Secret ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Secret "))
		}
	}
	return ""
}

// trivyRedactedMessage replaces the credential of a message with its mask.
func trivyRedactedMessage(message, secret string) string {
	if message == "" {
		return ""
	}
	if secret == "" {
		return "Secret detected (the matched value is withheld)"
	}
	return strings.ReplaceAll(message, secret, maskSecret(secret))
}

// trivySbomResponse assembles the payload of the SBOM tool: the document,
// the digest of the file and the metadata of the scan.
func trivySbomResponse(sbomPath string, data []byte, sum string) map[string]any {
	res := map[string]any{
		"sbom_path":   sbomPath,
		"sbom_sha256": sum,
		"sbom_format": "cyclonedx",
		"sbom_bytes":  len(data),
	}
	if len(data) <= maxSbomBytes {
		res["sbom"] = trivySbomDocument(data)
	} else {
		// The document is too big for the response: the file and its
		// digest are the deliverable.
		res["sbom_truncated"] = true
	}
	res["sbom_metadata"] = trivySbomMetadata(data)
	res["summary"] = fmt.Sprintf("CycloneDX SBOM generated (%d bytes, sha256 %s)", len(data), sum)
	return res
}

// trivySbomDocument decodes a CycloneDX document.
func trivySbomDocument(data []byte) map[string]any {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return map[string]any{"raw": string(data)}
	}
	return doc
}

// trivySbomMetadata reads the identity of a CycloneDX document: the tool
// that produced it, its version and the timestamp of the scan.
func trivySbomMetadata(data []byte) map[string]any {
	metadata := map[string]any{}
	var doc struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Tools     []struct {
				Vendor  string `json:"vendor"`
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"tools"`
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return metadata
	}
	metadata["bom_format"] = doc.BOMFormat
	metadata["spec_version"] = doc.SpecVersion
	metadata["serial_number"] = doc.SerialNumber
	metadata["timestamp"] = doc.Metadata.Timestamp
	metadata["component"] = doc.Metadata.Component.Name
	if doc.Metadata.Component.Version != "" {
		metadata["component_version"] = doc.Metadata.Component.Version
	}
	metadata["components_count"] = len(doc.Components)
	var tools []map[string]any
	for _, tool := range doc.Metadata.Tools {
		tools = append(tools, map[string]any{
			"vendor":  tool.Vendor,
			"name":    tool.Name,
			"version": tool.Version,
		})
	}
	metadata["tools"] = tools
	return metadata
}

// ————— Trivy JSON report (the cluster pass has no SARIF writer) —————

type trivyJSONReport struct {
	SchemaVersion int             `json:"SchemaVersion"`
	ArtifactName  string          `json:"ArtifactName"`
	ArtifactType  string          `json:"ArtifactType"`
	Results       []trivyJSONItem `json:"Results"`
}

type trivyJSONItem struct {
	Target            string               `json:"Target"`
	Class             string               `json:"Class"`
	Type              string               `json:"Type"`
	Vulnerabilities   []trivyJSONVuln      `json:"Vulnerabilities"`
	Misconfigurations []trivyJSONMisconfig `json:"Misconfigurations"`
	Secrets           []trivyJSONSecret    `json:"Secrets"`
	Licenses          []trivyJSONLicense   `json:"Licenses"`
}

type trivyJSONVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
}

type trivyJSONMisconfig struct {
	ID            string `json:"ID"`
	AVDID         string `json:"AVDID"`
	Title         string `json:"Title"`
	Description   string `json:"Description"`
	Message       string `json:"Message"`
	Namespace     string `json:"Namespace"`
	Resolution    string `json:"Resolution"`
	Severity      string `json:"Severity"`
	PrimaryURL    string `json:"PrimaryURL"`
	Status        string `json:"Status"`
	CauseMetadata struct {
		StartLine int `json:"StartLine"`
		EndLine   int `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type trivyJSONSecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

type trivyJSONLicense struct {
	Severity string `json:"Severity"`
	Category string `json:"Category"`
	PkgName  string `json:"PkgName"`
	Name     string `json:"Name"`
	Link     string `json:"Link"`
	FilePath string `json:"FilePath"`
}

// parseTrivyJSON normalizes the JSON report of Trivy into canonical
// findings.
//
// The cluster pass of `trivy k8s` has no SARIF writer: its JSON report is
// the only source of its results.
func parseTrivyJSON(data []byte) ([]Finding, error) {
	var report trivyJSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode trivy report: %w", err)
	}

	var findings []Finding
	for _, item := range report.Results {
		for _, v := range item.Vulnerabilities {
			findings = append(findings, trivyJSONVulnFinding(item, v))
		}
		for _, m := range item.Misconfigurations {
			findings = append(findings, trivyJSONMisconfigFinding(item, m))
		}
		for _, s := range item.Secrets {
			findings = append(findings, trivyJSONSecretFinding(item, s))
		}
		for _, l := range item.Licenses {
			findings = append(findings, trivyJSONLicenseFinding(item, l))
		}
	}
	return findings, nil
}

func trivyJSONVulnFinding(item trivyJSONItem, v trivyJSONVuln) Finding {
	title := v.Title
	if title == "" {
		title = v.VulnerabilityID
	}
	evidence := map[string]any{
		"rule":              v.VulnerabilityID,
		"package":           v.PkgName,
		"installed_version": v.InstalledVersion,
		"target":            item.Target,
	}
	if v.FixedVersion != "" {
		evidence["fixed_version"] = v.FixedVersion
	}
	if v.PrimaryURL != "" {
		evidence["reference"] = v.PrimaryURL
	}
	tags := []string{"dependency", "supply-chain", "vulnerability"}
	return Finding{
		Source:     "code.deps",
		SourceTool: "code.deps",
		RuleID:     "trivy:" + v.VulnerabilityID,
		Title:      title,
		Severity:   normalizeSeverity(v.Severity),
		Confidence: ConfidenceProbable,
		Target:     item.Target,
		Vector:     item.Target,
		Evidence:   evidence,
		Tags:       dedupeTags(tags),
		References: v.References,
	}
}

func trivyJSONMisconfigFinding(item trivyJSONItem, m trivyJSONMisconfig) Finding {
	id := m.ID
	if id == "" {
		id = m.AVDID
	}
	title := m.Title
	if title == "" {
		title = id
	}
	evidence := map[string]any{
		"rule":   id,
		"target": item.Target,
	}
	if m.Message != "" {
		evidence["message"] = m.Message
	}
	if m.Namespace != "" {
		evidence["namespace"] = m.Namespace
	}
	if m.Resolution != "" {
		evidence["remediation"] = m.Resolution
	}
	line := m.CauseMetadata.StartLine
	target := item.Target
	if line > 0 {
		evidence["line"] = line
	}
	return Finding{
		Source:      "code.iac",
		SourceTool:  "code.iac",
		RuleID:      "trivy:" + id,
		Title:       title,
		Severity:    normalizeSeverity(m.Severity),
		Confidence:  ConfidenceProbable,
		Target:      target,
		Vector:      sarifVector(target, line),
		Evidence:    evidence,
		Remediation: m.Resolution,
		Tags:        dedupeTags([]string{"misconfiguration", "iac", "supply-chain"}),
		References:  stringListOrNil(m.PrimaryURL),
	}
}

func trivyJSONSecretFinding(item trivyJSONItem, s trivyJSONSecret) Finding {
	evidence := map[string]any{
		"rule":   s.RuleID,
		"file":   item.Target,
		"line":   s.StartLine,
		"secret": maskSecret(s.Match),
	}
	if hash := secretHash(s.Match); hash != "" {
		evidence["secretHash"] = hash
	}
	title := s.Title
	if title == "" {
		title = s.RuleID
	}
	return Finding{
		Source:     "code.secrets",
		SourceTool: "code.secrets",
		RuleID:     "trivy:" + s.RuleID,
		Title:      "Hardcoded secret: " + title,
		Severity:   SeverityCritical,
		Confidence: trivySecretConfidence(s.RuleID),
		Target:     item.Target,
		Vector:     sarifVector(item.Target, s.StartLine),
		Evidence:   evidence,
		Tags:       dedupeTags([]string{"secret-exposure", "hardcoded-secret"}),
	}
}

func trivyJSONLicenseFinding(item trivyJSONItem, l trivyJSONLicense) Finding {
	evidence := map[string]any{
		"rule":     l.Name,
		"license":  l.Name,
		"category": l.Category,
		"package":  l.PkgName,
		"target":   item.Target,
	}
	if l.FilePath != "" {
		evidence["file"] = l.FilePath
	}
	return Finding{
		Source:     "code.licenses",
		SourceTool: "code.licenses",
		RuleID:     "trivy:license:" + l.Name,
		Title:      fmt.Sprintf("License %s (%s) in %s", l.Name, l.Category, l.PkgName),
		Severity:   normalizeSeverity(l.Severity),
		Confidence: ConfidenceProbable,
		Target:     item.Target,
		Vector:     item.Target,
		Evidence:   evidence,
		Tags:       dedupeTags([]string{"license", "supply-chain"}),
		References: stringListOrNil(l.Link),
	}
}

// stringListOrNil returns a one element slice, or nothing when the value is
// empty.
func stringListOrNil(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return []string{value}
}

// gitleaksRunFailed decides whether a gitleaks run really scanned something.
// Gitleaks exits with 1 both when it finds a secret and when it fails (the
// path is not a repository, for instance), so the exit code alone is not a
// verdict: the report and the log decide.
func gitleaksRunFailed(r *runResult, reportExists bool) bool {
	if r.ExitCode >= 2 {
		return true
	}
	if !reportExists {
		return true
	}
	stderr := strings.ToLower(r.Stderr)
	return strings.Contains(stderr, "failed to scan") || strings.Contains(stderr, "not a git repository")
}

// semgrepPacks reports the rule sets a semgrep run used, for traceability.
func semgrepPacks(rules string) []string {
	if rules != "" {
		return []string{rules}
	}
	return append([]string{}, semgrepRulePacks...)
}
