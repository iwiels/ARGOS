package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

// CodeQL is the interprocedural and cross-file engine: Semgrep Community
// Edition only analyzes the inside of a single function or file, which is
// exactly where the expensive findings live (IDOR, broken authorization,
// path traversal and command injection that span two modules).
//
// The CLI is open source and runs locally without telemetry, but its terms
// of service restrict how it can be distributed. Argos therefore never
// bundles it: a CodeQL CLI already installed by the operator wins, and the
// on-demand download is the fallback for the installations that do not have
// one yet.

// codeqlLanguage ties the language identifier CodeQL expects to the query
// pack that carries its suites and to the file extensions that identify it
// in a source tree.
type codeqlLanguage struct {
	// ID is the value of --language.
	ID string
	// Pack is the suffix of the query pack (codeql/<pack>-queries) and the
	// prefix of the suite files (codeql-suites/<pack>-security-extended.qls).
	Pack string
	// Exts are the source file extensions of the language.
	Exts []string
	// Extractors are the extractor pack names that can analyze the language.
	Extractors []string
	// Interpreted marks the languages whose database needs no build: the
	// extractor reads the source tree alone.
	Interpreted bool
	// OnlyUnder restricts the language to the files under one of these path
	// fragments. The Actions workflows share the YAML extension with every
	// other configuration file.
	OnlyUnder []string
}

// codeqlLanguages are the languages CodeQL analyzes.
//
// PHP is deliberately absent: CodeQL has no PHP extractor, so pretending
// otherwise would report a coverage that does not exist.
var codeqlLanguages = []codeqlLanguage{
	{ID: "javascript-typescript", Pack: "javascript", Exts: []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"},
		Extractors: []string{"javascript"}, Interpreted: true},
	{ID: "python", Pack: "python", Exts: []string{".py", ".pyi"},
		Extractors: []string{"python"}, Interpreted: true},
	{ID: "go", Pack: "go", Exts: []string{".go"},
		Extractors: []string{"go"}},
	{ID: "java-kotlin", Pack: "java", Exts: []string{".java", ".kt", ".kts"},
		Extractors: []string{"java"}},
	{ID: "csharp", Pack: "csharp", Exts: []string{".cs"},
		Extractors: []string{"csharp"}},
	{ID: "c-cpp", Pack: "cpp", Exts: []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".mm"},
		Extractors: []string{"cpp", "c"}},
	{ID: "ruby", Pack: "ruby", Exts: []string{".rb"},
		Extractors: []string{"ruby"}, Interpreted: true},
	{ID: "rust", Pack: "rust", Exts: []string{".rs"},
		Extractors: []string{"rust"}},
	{ID: "swift", Pack: "swift", Exts: []string{".swift"},
		Extractors: []string{"swift"}},
	{ID: "actions", Pack: "actions", Exts: []string{".yml", ".yaml"},
		Extractors: []string{"actions"}, OnlyUnder: []string{".github/workflows"}},
}

// codeqlDefaultSuites are the query suites code.semantic runs by default.
//
// security-extended adds the lower severity and lower precision security
// queries to the default suite of the language, and security-and-quality
// adds the maintainability and reliability ones on top of it. Together they
// cover the weakness classes a cross-file analysis is for.
var codeqlDefaultSuites = []string{"security-extended", "security-and-quality"}

// codeqlIgnoredDirs are the directories that never hold first-party source
// code: walking them costs time and only adds third-party findings.
var codeqlIgnoredDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	"target": true, ".venv": true, "venv": true, "__pycache__": true, ".codeql": true,
	".idea": true, ".vscode": true, ".next": true, ".nuget": true, "Pods": true,
	".gradle": true, ".mvn": true, "coverage": true, ".terraform": true,
}

// codeqlMaxScannedFiles bounds the language detection walk: a repository
// with hundreds of thousands of files does not need to be counted twice.
const codeqlMaxScannedFiles = 20000

// codeqlTime bounds of the tool.
const (
	codeqlDefaultTimeout = 600
	codeqlMaxTimeout     = 1800
)

// The status of a CodeQL run.
const (
	codeqlStatusCompleted   = "completed"
	codeqlStatusUnavailable = "unavailable"
	codeqlStatusUnsupported = "unsupported"
	codeqlStatusTimeout     = "timeout"
	codeqlStatusError       = "error"
	codeqlTermsAcceptedEnv  = "ARGOS_CODEQL_USE_ALLOWED"
)

func codeqlUseAllowed() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(codeqlTermsAcceptedEnv)), "true")
}

// codeqlLanguageOf resolves a language identifier (or one of its aliases)
// into the language description.
func codeqlLanguageOf(raw string) (codeqlLanguage, bool) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "js", "ts", "javascript", "typescript", "javascript-typescript":
		normalized = "javascript-typescript"
	case "java", "kotlin", "java-kotlin":
		normalized = "java-kotlin"
	case "c", "cpp", "c++", "c-cpp":
		normalized = "c-cpp"
	case "c#", "cs", "csharp":
		normalized = "csharp"
	}
	for _, lang := range codeqlLanguages {
		if lang.ID == normalized {
			return lang, true
		}
	}
	return codeqlLanguage{}, false
}

// codeqlLanguageIDs returns the identifiers of the supported languages.
func codeqlLanguageIDs() []string {
	out := make([]string, 0, len(codeqlLanguages))
	for _, lang := range codeqlLanguages {
		out = append(out, lang.ID)
	}
	return out
}

// detectCodeqlLanguages counts the source files of every supported language
// in the tree.
//
// It is the heuristic half of the language detection: it says what the
// repository is written in, and the resolver says what the CLI can analyze.
func detectCodeqlLanguages(root string) map[string]int {
	counts := map[string]int{}
	scanned := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if codeqlIgnoredDirs[name] || strings.HasPrefix(name, ".codeql") {
				return fs.SkipDir
			}
			return nil
		}
		scanned++
		if scanned > codeqlMaxScannedFiles {
			return fs.SkipAll
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == "" {
			return nil
		}
		slashed := filepath.ToSlash(path)
		for _, lang := range codeqlLanguages {
			if !codeqlHasExt(lang, ext) {
				continue
			}
			if !codeqlPathAllowed(lang, slashed) {
				continue
			}
			counts[lang.ID]++
		}
		return nil
	})
	return counts
}

func codeqlHasExt(lang codeqlLanguage, ext string) bool {
	for _, candidate := range lang.Exts {
		if candidate == ext {
			return true
		}
	}
	return false
}

// codeqlPathAllowed applies the per-language path restriction.
func codeqlPathAllowed(lang codeqlLanguage, slashed string) bool {
	if len(lang.OnlyUnder) == 0 {
		return true
	}
	for _, fragment := range lang.OnlyUnder {
		if strings.Contains(slashed, fragment) {
			return true
		}
	}
	return false
}

// codeqlResolveLanguages reads the extractor packs the CLI has installed.
//
// `codeql resolve languages --format=json` prints a JSON object whose keys
// are the extractor names and whose values are their locations.
func codeqlResolveLanguages(output string) map[string]bool {
	resolved := map[string]bool{}
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return resolved
	}
	var raw map[string][]string
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		// the CLI may print a banner before the JSON: take the object that
		// follows the first brace.
		if start := strings.Index(trimmed, "{"); start >= 0 {
			if err := json.Unmarshal([]byte(trimmed[start:]), &raw); err != nil {
				return resolved
			}
		} else {
			return resolved
		}
	}
	for name := range raw {
		resolved[strings.ToLower(strings.TrimSpace(name))] = true
	}
	return resolved
}

// codeqlLanguageAvailable reports whether the CLI can analyze the language.
func codeqlLanguageAvailable(lang codeqlLanguage, resolved map[string]bool) bool {
	if len(resolved) == 0 {
		return true
	}
	for _, extractor := range lang.Extractors {
		if resolved[extractor] {
			return true
		}
	}
	return false
}

// codeqlPickLanguage chooses the language to analyze.
//
// The language the caller asked for wins. Otherwise the dominant language
// of the tree wins, among the ones the CLI can actually analyze: a
// repository with more Python than TypeScript is a Python audit, and a
// language without an extractor is not an option at all.
func codeqlPickLanguage(root, requested string, resolved map[string]bool) (codeqlLanguage, bool) {
	if requested != "" {
		lang, ok := codeqlLanguageOf(requested)
		if !ok {
			return codeqlLanguage{}, false
		}
		return lang, true
	}
	counts := detectCodeqlLanguages(root)
	best := codeqlLanguage{}
	bestCount := 0
	for _, lang := range codeqlLanguages {
		count := counts[lang.ID]
		if count == 0 {
			continue
		}
		if !codeqlLanguageAvailable(lang, resolved) {
			continue
		}
		if count > bestCount {
			best = lang
			bestCount = count
		}
	}
	if bestCount == 0 {
		return codeqlLanguage{}, false
	}
	return best, true
}

// codeqlQuerySpec builds the query specifier of a suite for a language.
//
// The CodeQL CLI resolves a specifier as scope/name@range:path, and the
// suites of the standard packs live in codeql-suites/<pack>-<suite>.qls.
func codeqlQuerySpec(pack, suite string) string {
	return fmt.Sprintf("codeql/%s-queries:codeql-suites/%s-%s.qls", pack, pack, suite)
}

// codeqlQueries resolves the query specifiers of a run.
//
// The caller may pass suite names ("security-extended"), full specifiers
// ("codeql/java-queries:codeql-suites/java-security-extended.qls") or a
// mix of both. The default is the two security suites of the language.
func codeqlQueries(lang codeqlLanguage, requested string) []string {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		out := make([]string, 0, len(codeqlDefaultSuites))
		for _, suite := range codeqlDefaultSuites {
			out = append(out, codeqlQuerySpec(lang.Pack, suite))
		}
		return out
	}
	var out []string
	for _, part := range strings.Split(requested, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, ":") || strings.Contains(part, "/") {
			out = append(out, part)
			continue
		}
		out = append(out, codeqlQuerySpec(lang.Pack, part))
	}
	if len(out) == 0 {
		for _, suite := range codeqlDefaultSuites {
			out = append(out, codeqlQuerySpec(lang.Pack, suite))
		}
	}
	return out
}

// codeqlDatabaseArgs builds the `codeql database create` command line.
//
// The interpreted languages get --build-mode=none: asking CodeQL to build a
// project that does not need a build only makes the extraction fail.
func codeqlDatabaseArgs(dbPath, sourceRoot, language, buildCommand string) []string {
	args := []string{
		"database", "create",
		"--language=" + language,
		"--source-root=" + sourceRoot,
		"--overwrite",
	}
	if buildCommand != "" {
		args = append(args, "--command="+buildCommand)
	} else if codeqlLanguageInterpreted(language) {
		args = append(args, "--build-mode=none")
	}
	return append(args, dbPath)
}

// codeqlLanguageInterpreted reports whether the language needs no build.
func codeqlLanguageInterpreted(language string) bool {
	lang, ok := codeqlLanguageOf(language)
	return ok && lang.Interpreted
}

// codeqlAnalyzeArgs builds the `codeql database analyze` command line.
//
// --download lets the CLI fetch the query packs it is missing from the
// package registry: the bundle ships the extractors, not the suites.
func codeqlAnalyzeArgs(dbPath, output string, queries []string) []string {
	args := []string{
		"database", "analyze",
		"--format=sarif-latest",
		"--output=" + output,
		"--sarif-category=argos",
		"--threads=0",
		"--download",
	}
	args = append(args, dbPath)
	return append(args, queries...)
}

// codeqlBinaryFromPath returns the CodeQL CLI the operator installed.
//
// A CLI in the PATH wins over the on-demand download: the terms of service
// of the CodeQL CLI do not allow Argos to redistribute it, so the copy the
// user installed is the one that gets used.
func codeqlBinaryFromPath() string {
	names := []string{"codeql"}
	if runtime.GOOS == "windows" {
		names = []string{"codeql.exe", "codeql"}
	}
	for _, name := range names {
		path, err := exec.LookPath(name)
		if err != nil || path == "" {
			continue
		}
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(path), ".exe") {
			// the .cmd/.bat wrappers are for the interactive shell: they
			// cannot be executed directly.
			continue
		}
		return path
	}
	return ""
}

// codeqlInstallHint tells the operator how to get the CLI when it is not
// available.
func codeqlInstallHint() string {
	return "install the CodeQL CLI from https://github.com/github/codeql-cli-binaries/releases " +
		"(unpack it and put the `codeql` launcher in PATH) or let Argos download it after eligibility is confirmed; " +
		"CodeQL is disabled unless " + codeqlTermsAcceptedEnv + "=true. Set that variable only when the target and use " +
		"are permitted by the GitHub CodeQL Terms of Service (https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)."
}

// codeqlOutcome is the result of a CodeQL run.
type codeqlOutcome struct {
	// Status is what happened: completed, unavailable, unsupported, timeout
	// or error.
	Status string
	// Available is false when the CLI could not be used at all.
	Available bool
	// Reason explains why the CLI is not available.
	Reason string
	// Binary is the CLI that ran.
	Binary string
	// BinarySource is "path" or "downloaded".
	BinarySource string
	// Language is the language that was analyzed.
	Language string
	// Queries are the query specifiers that ran.
	Queries []string
	// Findings are the canonical findings of the analysis.
	Findings []Finding
	// Result is the outcome of the analyze command.
	Result *runResult
	// Duration is the wall time of the whole analysis.
	Duration time.Duration
	// Timeout is the effective timeout of the run.
	Timeout time.Duration
	// TimeoutSource is "requested" or "mcp": the MCP server caps every call
	// and the tighter of the two wins.
	TimeoutSource string
}

// codeqlOptions are the knobs of a CodeQL run.
type codeqlOptions struct {
	Path         string
	Language     string
	Queries      string
	BuildCommand string
	Timeout      int
}

// codeqlRun performs the whole CodeQL flow: resolve the CLI, detect the
// language, create the database, analyze it and normalize the SARIF.
//
// A missing CLI is not an error: the caller reports the degradation.
func codeqlRun(ctx context.Context, env *Env, opts codeqlOptions) codeqlOutcome {
	start := time.Now()
	out := codeqlOutcome{Status: codeqlStatusCompleted}
	if !codeqlUseAllowed() {
		out.Status = codeqlStatusUnavailable
		out.Available = false
		out.Reason = "CodeQL is disabled until the operator confirms that the target and use are permitted by the GitHub CodeQL Terms of Service; set " + codeqlTermsAcceptedEnv + "=true only for eligible use"
		return out
	}

	binary, source, err := codeqlResolveBinary(ctx, env)
	if err != nil {
		out.Status = codeqlStatusUnavailable
		out.Available = false
		out.Reason = err.Error()
		return out
	}
	out.Binary = binary
	out.BinarySource = source
	out.Available = true

	sourceRoot, err := filepath.Abs(opts.Path)
	if err != nil {
		out.Status = codeqlStatusError
		out.Available = false
		out.Reason = fmt.Sprintf("cannot resolve the source root %q: %v", opts.Path, err)
		return out
	}
	if fi, err := os.Stat(sourceRoot); err != nil || !fi.IsDir() {
		out.Status = codeqlStatusError
		out.Available = false
		out.Reason = fmt.Sprintf("the source root %q is not a directory", opts.Path)
		return out
	}

	resolved := codeqlResolveLanguages(codeqlResolveOutput(ctx, binary, sourceRoot))
	lang, ok := codeqlPickLanguage(sourceRoot, opts.Language, resolved)
	if !ok {
		out.Status = codeqlStatusUnsupported
		out.Available = false
		if opts.Language != "" {
			out.Reason = fmt.Sprintf("unsupported language %q: CodeQL analyzes %s", opts.Language, strings.Join(codeqlLanguageIDs(), ", "))
		} else {
			out.Reason = fmt.Sprintf("no CodeQL-supported language found under %q (CodeQL analyzes %s)", opts.Path, strings.Join(codeqlLanguageIDs(), ", "))
		}
		return out
	}
	out.Language = lang.ID
	out.Queries = codeqlQueries(lang, opts.Queries)

	workspace, err := os.MkdirTemp("", "codeql-*")
	if err != nil {
		out.Status = codeqlStatusError
		out.Available = false
		out.Reason = fmt.Sprintf("cannot create the workspace: %v", err)
		return out
	}
	defer os.RemoveAll(workspace)

	dbPath := filepath.Join(workspace, "codeql-db")
	sarifPath := filepath.Join(workspace, "results.sarif")
	timeout, timeoutSource := codeqlEffectiveTimeout(ctx, opts.Timeout)
	out.Timeout = timeout
	out.TimeoutSource = timeoutSource

	create := run(ctx, binary, codeqlArtifactRunOptions(
		codeqlDatabaseArgs(dbPath, sourceRoot, lang.ID, opts.BuildCommand), sourceRoot, workspace, timeout,
	))
	if create.ExitCode != 0 {
		out.Available = false
		out.Result = create
		out.Status = codeqlStatusOf(create, ctx)
		out.Reason = fmt.Sprintf("codeql database create failed (exit %d): %s", create.ExitCode, codeqlTail(create.Stderr))
		out.Duration = time.Since(start)
		return out
	}

	analyze := run(ctx, binary, codeqlArtifactRunOptions(
		codeqlAnalyzeArgs(dbPath, sarifPath, out.Queries), sourceRoot, workspace, timeout,
	))
	out.Result = analyze
	out.Duration = time.Since(start)

	data, err := os.ReadFile(sarifPath)
	if err != nil || len(data) == 0 {
		out.Available = false
		if analyze.ExitCode != 0 {
			out.Status = codeqlStatusOf(analyze, ctx)
			out.Reason = fmt.Sprintf("codeql database analyze failed (exit %d): %s", analyze.ExitCode, codeqlTail(analyze.Stderr))
		} else {
			out.Status = codeqlStatusError
			out.Reason = "codeql database analyze produced no report"
		}
		return out
	}

	findings, err := parseSarifReport(data, "code.semantic")
	if err != nil {
		out.Available = false
		out.Status = codeqlStatusError
		out.Reason = fmt.Sprintf("cannot parse the CodeQL report: %v", err)
		return out
	}
	out.Findings = codeqlFindings(findings, lang)
	return out
}

func codeqlArtifactRunOptions(args []string, sourceRoot, artifactDir string, timeout time.Duration) runOptions {
	return runOptions{
		Args:        args,
		Timeout:     timeout,
		Dir:         sourceRoot,
		ArtifactDir: artifactDir,
	}
}

// codeqlEffectiveTimeout resolves the timeout of a run.
//
// The MCP server caps every call (ARGOS_MCP_TIMEOUT_MS, five minutes by
// default): a tighter deadline than the requested one wins, and the run says
// which of the two was applied.
func codeqlEffectiveTimeout(ctx context.Context, requested int) (time.Duration, string) {
	timeout := time.Duration(clampTimeoutRange(requested, codeqlDefaultTimeout, codeqlMaxTimeout)) * time.Second
	source := "requested"
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
			source = "mcp"
		}
	}
	return timeout, source
}

// codeqlStatusOf decides the status of a failed run.
func codeqlStatusOf(r *runResult, ctx context.Context) string {
	if r != nil && r.TimedOut {
		return codeqlStatusTimeout
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return codeqlStatusTimeout
	}
	return codeqlStatusError
}

// codeqlResolveBinary finds the CLI to run.
//
// The PATH wins; the on-demand download is the fallback for the
// installations that do not have one.
func codeqlResolveBinary(ctx context.Context, env *Env) (string, string, error) {
	if path := codeqlBinaryFromPath(); path != "" {
		return path, "path", nil
	}
	if env == nil || env.Downloader == nil {
		return "", "", errors.New("the tool downloader is not configured")
	}
	spec := env.Spec("codeql")
	if spec == nil {
		return "", "", errors.New("the codeql tool is not configured")
	}
	path, _, err := env.Downloader.Ensure(ctx, spec)
	if err != nil {
		return "", "", err
	}
	return path, "downloaded", nil
}

// codeqlResolveOutput runs `codeql resolve languages` and returns its
// output. A failure is not fatal: the heuristic detection still works.
func codeqlResolveOutput(ctx context.Context, binary, sourceRoot string) string {
	r := run(ctx, binary, runOptions{
		Args:    []string{"resolve", "languages", "--format=json"},
		Timeout: 120 * time.Second,
	})
	if r.ExitCode != 0 {
		return ""
	}
	return r.Output
}

// codeqlTail keeps the last lines of an error message.
func codeqlTail(text string) string {
	cleaned := strings.TrimSpace(text)
	if cleaned == "" {
		return "no output"
	}
	lines := strings.Split(cleaned, "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return strings.Join(lines, " | ")
}

// codeqlFindings normalizes the findings of a CodeQL run.
//
// The shared SARIF parser assumes the Semgrep engine when it prefixes the
// rule identifiers; CodeQL is not that engine, so the prefix is rewritten
// here. The CWE, the severity and the dataflow come from the SARIF itself:
// the CodeQL taxonomies carry the weakness and the code flows carry the
// cross-file path that justifies the finding.
func codeqlFindings(findings []Finding, lang codeqlLanguage) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		f.Source = "code.semantic"
		f.SourceTool = "code.semantic"
		f.RuleID = codeqlRuleID(f.RuleID)
		f.Tags = dedupeTags(append(f.Tags, "semantic-analysis", "codeql", lang.Pack))
		if f.Confidence == ConfidencePossible {
			// a cross-file finding is a real dataflow, not a shape match:
			// the engine followed the value from the source to the sink.
			f.Confidence = ConfidenceProbable
		}
		out = append(out, f)
	}
	return out
}

// codeqlRuleID renames the rule identifier of a finding.
func codeqlRuleID(parsed string) string {
	if idx := strings.Index(parsed, ":"); idx >= 0 {
		return "codeql:" + parsed[idx+1:]
	}
	return "codeql:" + parsed
}

// clampTimeoutRange clamps a timeout to a range that is not the default one
// of the web tools: the CodeQL analysis runs for minutes.
func clampTimeoutRange(sec, def, max int) int {
	if sec <= 0 {
		return def
	}
	if sec > max {
		return max
	}
	return sec
}

// codeMergeKey identifies a finding across engines.
//
// The weakness, the file and the line: two engines that report the same
// weakness at the same place are the same finding, and reporting it twice
// only inflates the count the client reads.
func codeMergeKey(f Finding) string {
	line := 0
	if value, ok := f.Evidence["line"].(int); ok {
		line = value
	}
	return fmt.Sprintf("%s|%s|%d", f.CWE, f.Target, line)
}

// codeMergeFindings merges the findings of several engines.
func codeMergeFindings(groups ...[]Finding) []Finding {
	var out []Finding
	index := map[string]int{}
	for _, group := range groups {
		for _, f := range group {
			key := codeMergeKey(f)
			if pos, ok := index[key]; ok {
				out[pos] = codeMergeFinding(out[pos], f)
				continue
			}
			index[key] = len(out)
			out = append(out, f)
		}
	}
	return out
}

func codeAnalyzeStatus(semgrepAvailable, codeqlAvailable bool) string {
	if semgrepAvailable && codeqlAvailable {
		return "completed"
	}
	if semgrepAvailable || codeqlAvailable {
		return "partial"
	}
	return "error"
}

// codeMergeFinding completes a finding with what the second engine knew.
func codeMergeFinding(base, extra Finding) Finding {
	for key, value := range extra.Evidence {
		if _, ok := base.Evidence[key]; !ok {
			base.Evidence[key] = value
		}
	}
	tools := codeEngineList(base.Evidence["sourceTools"])
	if base.SourceTool != "" && !containsString(tools, base.SourceTool) {
		tools = append(tools, base.SourceTool)
	}
	if extra.SourceTool != "" && !containsString(tools, extra.SourceTool) {
		tools = append(tools, extra.SourceTool)
	}
	base.Evidence["sourceTools"] = tools
	if severityRank(extra.Severity) > severityRank(base.Severity) {
		base.Severity = extra.Severity
	}
	if base.Confidence == ConfidencePossible && extra.Confidence != ConfidencePossible {
		base.Confidence = extra.Confidence
	}
	if base.CWE == "" {
		base.CWE = extra.CWE
	}
	if len(base.OWASP) == 0 {
		base.OWASP = extra.OWASP
	}
	if base.Remediation == "" {
		base.Remediation = extra.Remediation
	}
	if base.CVSS == nil {
		base.CVSS = extra.CVSS
	}
	return base
}

func codeEngineList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// runSemgrep executes a semgrep scan and normalizes its findings.
func runSemgrep(ctx context.Context, env *Env, targetPath, rules string, timeout int) ([]Finding, *runResult, bool) {
	bin, installed, e := env.Binary(ctx, "semgrep")
	if e != nil {
		return nil, &runResult{ExitCode: -1, Stderr: e.Message}, false
	}
	sourceRoot, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, &runResult{ExitCode: -1, Stderr: err.Error()}, installed
	}
	artifactDir, err := os.MkdirTemp("", "argos-semgrep-artifacts-")
	if err != nil {
		return nil, &runResult{ExitCode: -1, Stderr: err.Error()}, installed
	}
	defer os.RemoveAll(artifactDir)
	tmpJSON, err := os.CreateTemp(artifactDir, "semgrep-*.sarif")
	if err != nil {
		return nil, &runResult{ExitCode: -1, Stderr: err.Error()}, installed
	}
	tmpPath := tmpJSON.Name()
	tmpJSON.Close()

	r := run(ctx, bin, semgrepArtifactRunOptions(rules, sourceRoot, tmpPath, time.Duration(timeout)*time.Second))
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		markRunIncomplete(r, "Semgrep SARIF report could not be read: "+err.Error())
		return nil, r, installed
	}
	if len(data) == 0 {
		markRunIncomplete(r, "Semgrep returned no SARIF report")
		return nil, r, installed
	}
	findings, err := parseSarifReport(data, "code.sast")
	if err != nil {
		markRunIncomplete(r, "Semgrep returned an invalid SARIF report: "+err.Error())
		return nil, r, installed
	}
	return findings, r, installed
}

func semgrepArtifactRunOptions(rules, sourceRoot, reportPath string, timeout time.Duration) runOptions {
	return runOptions{
		Args:        semgrepArgs(rules, sourceRoot, reportPath),
		Timeout:     timeout,
		Dir:         sourceRoot,
		ArtifactDir: filepath.Dir(reportPath),
	}
}

// RegisterCodeQL registers the semantic analysis tools.
//
// It is called from RegisterCodeScan: the registration of the code tools
// lives in one place so the tool list of the server stays coherent.
func RegisterCodeQL(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "code.semantic",
			Description: "Interprocedural and cross-file semantic analysis of repository source code with the CodeQL CLI " +
				"(SARIF output). Finds the weaknesses a per-function scanner cannot see: IDOR, broken authorization, " +
				"path traversal and command injection that span modules. Reports the dataflow of every finding.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":          {Type: "string", Description: "Source directory to analyze (default '.')"},
					"language":      {Type: "string", Description: "Language to analyze: " + strings.Join(codeqlLanguageIDs(), ", ") + " (default: the dominant language of the tree)"},
					"queries":       {Type: "string", Description: "Comma separated query suites or specifiers (default: security-extended, security-and-quality)"},
					"build_command": {Type: "string", Description: "Build command for the compiled languages (C/C++, Java, C#, Go)"},
					"timeout":       {Type: "integer", Description: "Timeout in seconds (default 600, max 1800). The MCP server caps every call: raise ARGOS_MCP_TIMEOUT_MS for the long analyses."},
				},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Path         string `json:"path"`
				Language     string `json:"language"`
				Queries      string `json:"queries"`
				BuildCommand string `json:"build_command"`
				Timeout      int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			targetPath := input.Path
			if targetPath == "" {
				targetPath = "."
			}
			if input.Language != "" {
				if _, ok := codeqlLanguageOf(input.Language); !ok {
					return nil, invalidParams(fmt.Errorf("unknown language %q: CodeQL analyzes %s", input.Language, strings.Join(codeqlLanguageIDs(), ", ")))
				}
			}

			out := codeqlRun(toolContext(ctx), env, codeqlOptions{
				Path:         targetPath,
				Language:     input.Language,
				Queries:      input.Queries,
				BuildCommand: input.BuildCommand,
				Timeout:      input.Timeout,
			})

			res := map[string]interface{}{
				"tool":        "code.semantic",
				"target":      targetPath,
				"duration_ms": out.Duration.Milliseconds(),
			}
			if out.Status != codeqlStatusCompleted {
				res["status"] = out.Status
				res["available"] = out.Available
				res["reason"] = out.Reason
				res["summary"] = "CodeQL did not complete: " + out.Reason
				res["findings"] = []map[string]any{}
				if out.Status == codeqlStatusUnavailable {
					res["install_hint"] = codeqlInstallHint()
				}
				if out.Status == codeqlStatusTimeout {
					res["timeout_hint"] = "raise ARGOS_MCP_TIMEOUT_MS (the MCP server caps every call at five minutes by default) or lower the timeout of the tool"
				}
				return res, nil
			}

			findings, truncated := capFindings(out.Findings)
			res["status"] = codeqlStatusCompleted
			res["available"] = true
			res["language"] = out.Language
			res["queries"] = out.Queries
			res["engine"] = out.BinarySource
			res["timeout_ms"] = out.Timeout.Milliseconds()
			res["timeout_source"] = out.TimeoutSource
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d semantic findings detected", len(findings))
			if out.Result != nil {
				res["exit_code"] = out.Result.ExitCode
				if out.Result.TimedOut {
					res["status"] = codeqlStatusTimeout
				}
			}
			env.publishFindings(res, findings)
			return res, nil
		},
	)

	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "code.analyze",
			Description: "Deep static analysis of repository source code: runs Semgrep (per-function rules) and CodeQL " +
				"(interprocedural and cross-file) and merges the findings without duplicates, keeping the engine that " +
				"produced every one. This is the entry point of the deep analysis phase.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":          {Type: "string", Description: "Source directory to analyze (default '.')"},
					"language":      {Type: "string", Description: "Language for the CodeQL pass: " + strings.Join(codeqlLanguageIDs(), ", ")},
					"queries":       {Type: "string", Description: "Comma separated CodeQL query suites (default: security-extended, security-and-quality)"},
					"rules":         {Type: "string", Description: "Semgrep rule pack (default: p/security-audit, p/owasp-top-ten, p/cwe-top-25, p/trailofbits)"},
					"build_command": {Type: "string", Description: "Build command for the compiled languages (C/C++, Java, C#, Go)"},
					"timeout":       {Type: "integer", Description: "Timeout in seconds (default 600, max 1800). The MCP server caps every call: raise ARGOS_MCP_TIMEOUT_MS for the long analyses."},
				},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Path         string `json:"path"`
				Language     string `json:"language"`
				Queries      string `json:"queries"`
				Rules        string `json:"rules"`
				BuildCommand string `json:"build_command"`
				Timeout      int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			targetPath := input.Path
			if targetPath == "" {
				targetPath = "."
			}
			if input.Language != "" {
				if _, ok := codeqlLanguageOf(input.Language); !ok {
					return nil, invalidParams(fmt.Errorf("unknown language %q: CodeQL analyzes %s", input.Language, strings.Join(codeqlLanguageIDs(), ", ")))
				}
			}
			toolCtx := toolContext(ctx)

			semgrepFindings, semgrepRun, semgrepInstalled := runSemgrep(toolCtx, env, targetPath, input.Rules, clampTimeout(input.Timeout, 300))
			out := codeqlRun(toolCtx, env, codeqlOptions{
				Path:         targetPath,
				Language:     input.Language,
				Queries:      input.Queries,
				BuildCommand: input.BuildCommand,
				Timeout:      input.Timeout,
			})

			merged := codeMergeFindings(semgrepFindings, out.Findings)
			merged, truncated := capFindings(merged)
			semgrepAvailable := semgrepRun != nil && semgrepRun.ExitCode == 0
			codeqlAvailable := out.Status == codeqlStatusCompleted
			analysisStatus := codeAnalyzeStatus(semgrepAvailable, codeqlAvailable)

			res := map[string]interface{}{
				"tool":        "code.analyze",
				"target":      targetPath,
				"duration_ms": out.Duration.Milliseconds(),
				"truncated":   truncated,
				"status":      analysisStatus,
				"complete":    analysisStatus == "completed",
			}
			res["engines"] = map[string]interface{}{
				"code.sast": map[string]interface{}{
					"available": semgrepAvailable,
					"findings":  len(semgrepFindings),
					"installed": semgrepInstalled,
				},
				"code.semantic": map[string]interface{}{
					"available": codeqlAvailable,
					"status":    out.Status,
					"findings":  len(out.Findings),
					"language":  out.Language,
					"engine":    out.BinarySource,
				},
			}
			if out.Status != codeqlStatusCompleted {
				res["codeql_reason"] = out.Reason
				if out.Status == codeqlStatusUnavailable {
					res["codeql_install_hint"] = codeqlInstallHint()
				}
			}
			var incompleteReasons []string
			if !semgrepAvailable {
				reason := "Semgrep did not complete"
				if semgrepRun != nil && semgrepRun.Stderr != "" {
					reason += ": " + truncateStr(semgrepRun.Stderr, 500)
				}
				incompleteReasons = append(incompleteReasons, reason)
			}
			if !codeqlAvailable {
				incompleteReasons = append(incompleteReasons, "CodeQL did not complete: "+out.Reason)
			}
			if len(incompleteReasons) > 0 {
				res["incomplete_reasons"] = incompleteReasons
			}
			if semgrepRun != nil {
				res["exit_code"] = semgrepRun.ExitCode
			}
			res["summary"] = fmt.Sprintf("%d findings detected (%d Semgrep, %d CodeQL)", len(merged), len(semgrepFindings), len(out.Findings))
			if analysisStatus != "completed" {
				res["summary"] = fmt.Sprintf("%s; analysis %s", res["summary"], analysisStatus)
			}
			env.publishFindings(res, merged)
			return res, nil
		},
	)
}
