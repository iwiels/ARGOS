package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/guard"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/workerpreflight"
)

const (
	// preflightProbes is how many requests a scan sends against the target
	// before it starts. The circuit breaker needs a sample of responses to
	// decide, and five cheap GETs are the price of not hammering a target
	// that is already degraded.
	preflightProbes = 5
	// passiveProtocolTypes restricts the passive phase to the HTTP protocol
	// family: DNS, network, file, headless and code templates are out of the
	// safe phase.
	passiveProtocolTypes = "http"
	// passivePhaseTags are the recon-grade template classes the passive phase
	// runs when the caller does not ask for a specific set.
	passivePhaseTags = "exposure,misconfig,tech,detect"
	// passivePhaseExcludedTags are the intrusive template classes that never
	// run in the passive phase.
	passivePhaseExcludedTags = "dos,intrusive,fuzzing,default-login"
	// minPhaseBudget is the minimum time a phase of a scan may run.
	minPhaseBudget = 30 * time.Second
	// maxPassiveBudget is the maximum time the passive (recon-grade) phase
	// may take: it is the cheap sweep, the active phase is where the
	// coverage is.
	maxPassiveBudget = 60 * time.Second
)

// nucleiScanOptions holds the resolved knobs of a nuclei invocation.
type nucleiScanOptions struct {
	Tags               string
	Severities         []string
	Headless           bool
	FollowRedirects    bool
	ResumeFile         string
	RateLimit          int
	Concurrency        int
	TemplatesDir       string   // empty → nuclei falls back to its own template set
	ExtraTemplateDirs  []string // operator dirs and Argos packs, added to the set
	ExcludeTemplateIDs []string
	ExcludeTags        []string
	Passive            bool
	Stats              bool
}

// nucleiScanArgs builds the nuclei command line for a scan. The template
// directory is only passed when the community templates are available, so a
// failed download degrades to the nuclei built-in set instead of breaking the
// scan.
func nucleiScanArgs(target string, opts nucleiScanOptions) []string {
	args := []string{
		"-u", target, "-jsonl", "-silent", "-no-color",
		"-restrict-local-network-access", "-no-interactsh", "-disable-update-check",
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(opts.RateLimit))
	}
	if opts.Concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(opts.Concurrency))
	}
	if opts.Tags != "" {
		args = append(args, "-tags", opts.Tags)
	}
	if len(opts.Severities) > 0 {
		args = append(args, "-severity", strings.Join(opts.Severities, ","))
	}
	if dir := templateSet(opts); dir != "" {
		args = append(args, "-templates", dir)
	}
	if len(opts.ExcludeTemplateIDs) > 0 {
		args = append(args, "-eid", strings.Join(opts.ExcludeTemplateIDs, ","))
	}
	if len(opts.ExcludeTags) > 0 {
		args = append(args, "-etags", strings.Join(opts.ExcludeTags, ","))
	}
	if opts.Passive {
		args = append(args, "-pt", passiveProtocolTypes)
	}
	if opts.Headless {
		args = append(args, "-headless")
	}
	if opts.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	if opts.ResumeFile != "" {
		args = append(args, "-resume", opts.ResumeFile)
	}
	if opts.Stats {
		args = append(args, "-stats")
	}
	return args
}

// templateSet is the template list of a scan: the pinned community set, the
// Argos packs and the extra templates of the operator, when there are any.
func templateSet(opts nucleiScanOptions) string {
	dirs := make([]string, 0, 1+len(opts.ExtraTemplateDirs))
	if opts.TemplatesDir != "" {
		dirs = append(dirs, opts.TemplatesDir)
	}
	dirs = append(dirs, opts.ExtraTemplateDirs...)
	return strings.Join(dirs, ",")
}

// scanPhase is one nuclei invocation of a scan.
type scanPhase struct {
	name    string
	opts    nucleiScanOptions
	timeout time.Duration
}

func RegisterScan(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.scan",
			Description: "Template-driven vulnerability scan with nuclei (CVE, misconfig, exposure templates). Uses the pinned community nuclei-templates set when available and restricts local-network access. " +
				"Runs the passive (recon-grade) phase first and the active phase after it, reporting both separately. " +
				"A circuit breaker checks target health before and between phases; it does not observe requests while the external nuclei process is running.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":            {Type: "string", Description: "Target URL, e.g. https://example.com"},
					"tags":              {Type: "string", Description: "nuclei tags filter, e.g. sqli, xss, cve"},
					"severities":        {Type: "array", Items: &mcp.Items{Type: "string"}, Description: "Severities to run: info, low, medium, high, critical"},
					"severity":          {Type: "string", Description: "Deprecated: single minimum severity, use severities instead"},
					"exclude_templates": {Type: "array", Items: &mcp.Items{Type: "string"}, Description: "Templates to skip because another tool covers them (a path is a template id, a bare word is a tag, e.g. sqli)"},
					"custom_templates":  {Type: "string", Description: "Extra directory of custom nuclei templates, added to the pinned set"},
					"packs":             {Type: "array", Items: &mcp.Items{Type: "string"}, Description: "Argos template packs to run (see web.templates). Empty runs every enabled pack"},
					"passive":           {Type: "boolean", Description: "Run only the passive (recon-grade) phase, without active payloads"},
					"headless":          {Type: "boolean", Description: "Enable nuclei headless mode for browser-based templates (SPAs)"},
					"follow_redirects":  {Type: "boolean", Description: "Follow redirects while scanning"},
					"resume":            {Type: "boolean", Description: "Resume the scan from the nuclei resume file of the target"},
					"timeout":           {Type: "integer", Description: "Scan timeout in seconds (default 180, max 300)"},
					"rate_limit":        {Type: "integer", Description: "Maximum requests per second (default 10)"},
					"concurrency":       {Type: "integer", Description: "Maximum templates executed in parallel (default 25)"},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			scopedEnv, releaseScope, scopeError := scopedToolEnvironment(env, ctx)
			if scopeError != nil {
				return nil, scopeError
			}
			defer releaseScope()
			env := scopedEnv
			var input struct {
				Target           string          `json:"target"`
				Tags             string          `json:"tags"`
				Severity         string          `json:"severity"`
				Severities       json.RawMessage `json:"severities"`
				ExcludeTemplates json.RawMessage `json:"exclude_templates"`
				CustomTemplates  string          `json:"custom_templates"`
				Packs            json.RawMessage `json:"packs"`
				Headless         bool            `json:"headless"`
				FollowRedirects  bool            `json:"follow_redirects"`
				Resume           bool            `json:"resume"`
				Passive          bool            `json:"passive"`
				Timeout          int             `json:"timeout"`
				RateLimit        int             `json:"rate_limit"`
				Concurrency      int             `json:"concurrency"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			timeout := clampTimeout(input.Timeout, 180)
			scanCtx := toolContext(ctx)
			started := time.Now()

			// The circuit breaker of the engagement: shared by every tool of
			// the session, so an abort decided here is visible to the rest.
			breaker := SessionBreaker(env)

			// Pre-flight. The scan does not touch the target until the
			// breaker has seen enough responses to know that the target is
			// healthy: a target that is already answering 5xx must not be
			// hammered by a template engine.
			preflight, decision, preflightErr := runWorkerScanPreflight(scanCtx, breaker, target, preflightProbes)
			if preflightErr != nil {
				decision = guard.Decision{
					Continue: false,
					Action:   guard.ActionAbort,
					Reason:   "worker preflight failed: " + preflightErr.Error(),
				}
			}
			if !decision.Continue {
				emitBreakerEvent(env, "web.scan", target, decision, breaker)
				return abortedScanResult(target, decision, breaker, time.Since(started)), nil
			}

			// A WAF in front of the target softens the scan: lower rate
			// limit, no intrusive payloads.
			wafDetected := len(preflight.WAFVendors) > 0
			wafVendor := ""
			if wafDetected {
				wafVendor = preflight.WAFVendors[0]
				decision = breaker.Decision()
				emitBreakerEvent(env, "web.scan", target, decision, breaker)
			}

			cfg := loadNucleiScanConfig()
			opts := nucleiScanOptions{
				Tags:            input.Tags,
				Severities:      mergeSeverities(input.Severity, parseStringList(input.Severities)),
				Headless:        input.Headless,
				FollowRedirects: input.FollowRedirects,
				RateLimit:       input.RateLimit,
				Concurrency:     input.Concurrency,
			}
			if opts.RateLimit <= 0 {
				opts.RateLimit = cfg.RateLimit
			}
			if opts.Concurrency <= 0 {
				opts.Concurrency = cfg.Concurrency
			}

			extraDirs := make([]string, 0, 4)
			if custom := strings.TrimSpace(input.CustomTemplates); custom != "" {
				extraDirs = append(extraDirs, custom)
			}

			// Argos template packs: bundled data, enabled per registry and
			// selectable per scan. A pack that was requested but is unavailable
			// is an error: running a smaller scan than the caller asked for
			// without saying so would look like coverage.
			packsDir := ResolvePacksDir()
			requestedPacks := parseStringList(input.Packs)
			explicitPacks := len(requestedPacks) > 0
			if !explicitPacks {
				requestedPacks = cfg.Packs
			}
			packsRegistry, packsErr := LoadPacks(packsDir)
			var selectedPacks []Pack
			var packDirs, missingPacks []string
			packsWarning := ""
			if packsErr == nil {
				selectedPacks, packsErr = SelectPacks(packsRegistry, requestedPacks)
				if packsErr != nil && !explicitPacks {
					// A bad entry in argos.jsonc must not stop every scan, but it
					// must not pass unnoticed either: warn and use the defaults.
					packsWarning = packsErr.Error()
					log.Printf("argos-web: %s; falling back to the enabled packs", packsWarning)
					selectedPacks, packsErr = SelectPacks(packsRegistry, nil)
				}
			}
			if packsErr != nil && explicitPacks {
				return nil, invalidParams(fmt.Errorf("nuclei template packs: %w", packsErr))
			}
			if packsErr == nil {
				packDirs, missingPacks = PackDirs(packsDir, selectedPacks)
				extraDirs = append(extraDirs, packDirs...)
			}
			opts.ExtraTemplateDirs = extraDirs

			opts.ExcludeTemplateIDs, opts.ExcludeTags = splitExclusions(parseStringList(input.ExcludeTemplates))
			if input.Resume {
				opts.ResumeFile = resumeFileFor(target)
			}

			degraded := false
			degradedReason := ""
			if decision.Action == guard.ActionDegrade {
				degraded = true
				degradedReason = decision.Reason
				opts = degradeScanOptions(opts)
			}

			bin, installed, e := env.Binary(scanCtx, "nuclei")
			if e != nil {
				return nil, e
			}

			var templatesDir, templatesVersion string
			var templatesUpdated bool
			var templatesErr error
			if spec := env.Spec("nuclei-templates"); spec != nil {
				templatesDir, templatesVersion, templatesUpdated, templatesErr = env.Downloader.EnsureTemplates(scanCtx, spec)
			} else {
				templatesErr = fmt.Errorf("nuclei-templates spec is not configured")
			}
			if templatesErr != nil {
				log.Printf("argos-web: community templates unavailable, falling back to the nuclei built-in set: %v", templatesErr)
			} else {
				opts.TemplatesDir = templatesDir
				if templatesUpdated {
					log.Printf("argos-web: installed nuclei templates %s at %s", templatesVersion, templatesDir)
				}
			}

			// Traceability of the template set that ran the scan.
			applyTemplates := func(res map[string]interface{}) {
				if templatesErr != nil {
					res["templates_version"] = "embedded"
					res["templates_source"] = "embedded"
					res["templates_warning"] = templatesErr.Error()
					return
				}
				res["templates_version"] = templatesVersion
				res["templates_sha256"] = TemplatesSHA256(templatesDir)
				res["templates_source"] = "community"
			}

			// Traceability of the Argos packs that ran alongside the community
			// set: a scan that silently dropped a pack is not reproducible.
			applyPacks := func(res map[string]interface{}) {
				if packsErr != nil {
					res["templates_packs"] = []string{}
					res["templates_packs_source"] = "unavailable"
					res["templates_packs_error"] = packsErr.Error()
					return
				}
				ids := make([]string, 0, len(selectedPacks))
				for _, pack := range selectedPacks {
					ids = append(ids, pack.ID)
				}
				res["templates_packs"] = ids
				res["templates_packs_source"] = "bundled"
				res["templates_packs_sha256"] = PacksFingerprint(packsDir, packDirs)
				res["templates_packs_dir"] = packsDir
				if len(missingPacks) > 0 {
					res["templates_packs_missing"] = missingPacks
				}
				if packsWarning != "" {
					res["templates_packs_warning"] = packsWarning
				}
			}

			// Phase budgets: the passive phase and the active phase share the
			// timeout of the scan, so the scan never takes longer than the
			// operator allowed. The passive phase is time-boxed: it is the
			// cheap sweep, the active phase is where the coverage is.
			budget := time.Duration(timeout) * time.Second
			runPassive, runActive, passiveBudget, activeBudget := scanPhases(input.Passive, opts.Tags, budget)

			passiveOpts := opts
			passiveOpts.Passive = true
			passiveOpts.Stats = true
			passiveOpts.Headless = false
			passiveOpts.Tags = passivePhaseTagSet(opts.Tags)
			passiveOpts.ExcludeTags = mergeTags(opts.ExcludeTags, splitTags(passivePhaseExcludedTags))

			activeOpts := opts
			activeOpts.Stats = true

			var passiveRun *runResult
			var passiveFindings []Finding
			if runPassive {
				passiveRun, passiveFindings = runScanPhase(scanCtx, bin, target, scanPhase{
					name:    "passive",
					opts:    passiveOpts,
					timeout: passiveBudget,
				})
			}

			// The breaker decides again before the active phase: the passive
			// phase may have degraded the target.
			decision = breaker.Decision()
			effective := passiveOpts
			if !decision.Continue {
				emitBreakerEvent(env, "web.scan", target, decision, breaker)
				res := scanResult(scanOutcome{
					target:         target,
					agg:            aggregateRuns(passiveRun),
					passive:        passiveFindings,
					opts:           effective,
					degraded:       degraded,
					degradedReason: degradedReason,
					decision:       decision,
					breaker:        breaker,
					wafDetected:    wafDetected,
					wafVendor:      wafVendor,
					elapsed:        time.Since(started),
				})
				applyTemplates(res)
				applyPacks(res)
				return res, nil
			}
			if decision.Action == guard.ActionDegrade && !degraded {
				degraded = true
				degradedReason = decision.Reason
				activeOpts = degradeScanOptions(activeOpts)
				emitBreakerEvent(env, "web.scan", target, decision, breaker)
			}

			var activeRun *runResult
			var activeFindings []Finding
			if runActive {
				activeRun, activeFindings = runScanPhase(scanCtx, bin, target, scanPhase{
					name:    "active",
					opts:    activeOpts,
					timeout: activeBudget,
				})
				effective = activeOpts
			}

			res := scanResult(scanOutcome{
				target:         target,
				agg:            aggregateRuns(passiveRun, activeRun),
				passive:        passiveFindings,
				active:         activeFindings,
				opts:           effective,
				degraded:       degraded,
				degradedReason: degradedReason,
				decision:       decision,
				breaker:        breaker,
				wafDetected:    wafDetected,
				wafVendor:      wafVendor,
				elapsed:        time.Since(started),
			})
			applyTemplates(res)
			applyPacks(res)
			if installed {
				res["installed"] = "nuclei " + env.Spec("nuclei").Version
			}
			return res, nil
		},
	)
}

func runWorkerScanPreflight(ctx context.Context, breaker *guard.Breaker, target string, probes int) (workerpreflight.Result, guard.Decision, error) {
	if breaker == nil {
		breaker = guard.New(guard.Options{})
	}
	decision := breaker.Decision()
	if !decision.Continue {
		return workerpreflight.Result{}, decision, nil
	}
	if probes < 1 || probes > 20 {
		return workerpreflight.Result{}, guard.Decision{}, fmt.Errorf("preflight probe count is invalid")
	}

	result := run(ctx, "/usr/local/bin/argos-worker-preflight", runOptions{
		Args:    []string{"--target", target, "--probes", strconv.Itoa(probes)},
		Timeout: 45 * time.Second,
		MaxOut:  64 << 10,
	})
	if result.TimedOut {
		return workerpreflight.Result{}, guard.Decision{}, fmt.Errorf("scope-gateway worker timed out")
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(result.Stderr)
		if detail == "" {
			detail = fmt.Sprintf("worker exited with code %d", result.ExitCode)
		}
		return workerpreflight.Result{}, guard.Decision{}, fmt.Errorf("%s", detail)
	}
	if result.OutputTruncated {
		return workerpreflight.Result{}, guard.Decision{}, fmt.Errorf("worker preflight output was truncated")
	}

	var preflight workerpreflight.Result
	decoder := json.NewDecoder(strings.NewReader(result.Output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&preflight); err != nil {
		return workerpreflight.Result{}, guard.Decision{}, fmt.Errorf("invalid worker preflight response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return workerpreflight.Result{}, guard.Decision{}, fmt.Errorf("worker preflight returned trailing JSON data")
		}
		return workerpreflight.Result{}, guard.Decision{}, fmt.Errorf("invalid trailing worker preflight data: %w", err)
	}
	if err := workerpreflight.ValidateResult(preflight, target, probes); err != nil {
		return workerpreflight.Result{}, guard.Decision{}, err
	}

	for _, probe := range preflight.Probes {
		decision = breaker.Observe(probe.Status, probe.LatencyMS)
		if !decision.Continue {
			return preflight, decision, nil
		}
	}
	for _, vendor := range preflight.WAFVendors {
		breaker.ObserveWAFVendor(vendor)
	}
	return preflight, breaker.Decision(), nil
}

// runScanPhase runs one nuclei phase and parses its findings.
func runScanPhase(ctx context.Context, bin, target string, phase scanPhase) (*runResult, []Finding) {
	args := nucleiScanArgs(target, phase.opts)
	r := run(ctx, bin, runOptions{Args: args, Timeout: phase.timeout})
	return r, parseNuclei(r.Output, target, "web.scan")
}

// scanPhases decides which phases of a scan run and how much time each of
// them gets.
//
// A scan without tags runs the passive phase first (the recon-grade sweep)
// and then the active phase. A scan that already declares its template set
// runs that set only: the passive sweep would be traffic the operator did
// not ask for.
func scanPhases(passiveOnly bool, userTags string, budget time.Duration) (runPassive, runActive bool, passiveBudget, activeBudget time.Duration) {
	runPassive = passiveOnly || strings.TrimSpace(userTags) == ""
	runActive = !passiveOnly
	passiveBudget, activeBudget = budget, budget
	if !runPassive || !runActive {
		return runPassive, runActive, passiveBudget, activeBudget
	}
	passiveBudget = budget / 3
	if passiveBudget > maxPassiveBudget {
		passiveBudget = maxPassiveBudget
	}
	if passiveBudget < minPhaseBudget {
		passiveBudget = minPhaseBudget
	}
	activeBudget = budget - passiveBudget
	if activeBudget < minPhaseBudget {
		activeBudget = minPhaseBudget
	}
	return runPassive, runActive, passiveBudget, activeBudget
}

// degradeScanOptions softens a scan: half the rate limit, half the
// concurrency, no headless browser and no intrusive payload classes.
func degradeScanOptions(opts nucleiScanOptions) nucleiScanOptions {
	if opts.RateLimit > 1 {
		opts.RateLimit = opts.RateLimit / 2
	}
	if opts.Concurrency > 1 {
		opts.Concurrency = opts.Concurrency / 2
	}
	opts.Headless = false
	opts.ExcludeTags = mergeTags(opts.ExcludeTags, splitTags(passivePhaseExcludedTags))
	return opts
}

// passivePhaseTagSet returns the template classes of the passive phase: the
// recon-grade ones, unless the caller asked for a specific set.
func passivePhaseTagSet(userTags string) string {
	if strings.TrimSpace(userTags) != "" {
		return userTags
	}
	return passivePhaseTags
}

// splitExclusions routes the excluded templates to the right nuclei flag: an
// entry that looks like a path is a template id (-eid) and a bare word is a
// tag (-etags), which is how the operator excludes the classes another tool
// already covers (e.g. "sqli" before running web.sqli).
func splitExclusions(values []string) (ids []string, tags []string) {
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		lower := strings.ToLower(value)
		if strings.Contains(value, "/") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			ids = append(ids, value)
			continue
		}
		tags = append(tags, lower)
	}
	return ids, tags
}

// splitTags splits a comma separated list of tags.
func splitTags(value string) []string {
	out := make([]string, 0)
	for _, part := range strings.Split(value, ",") {
		tag := strings.ToLower(strings.TrimSpace(part))
		if tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// mergeTags merges tag lists without repeating entries.
func mergeTags(groups ...[]string) []string {
	seen := map[string]bool{}
	out := make([]string, 0)
	for _, group := range groups {
		for _, tag := range group {
			value := strings.ToLower(strings.TrimSpace(tag))
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// mergeSeverities merges the legacy single severity with the list.
func mergeSeverities(legacy string, list []string) []string {
	merged := mergeTags(list)
	if legacy = strings.ToLower(strings.TrimSpace(legacy)); legacy != "" {
		merged = mergeTags([]string{legacy}, merged)
	}
	return merged
}

// parseStringList reads a JSON value that may be a string or an array of
// strings into a slice of non-empty strings.
func parseStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	return stringList(value)
}

// resumeFileFor returns the path of the nuclei resume file of a target: the
// same target always resumes the same file, so an interrupted scan can
// continue where it stopped.
func resumeFileFor(target string) string {
	sum := sha256.Sum256([]byte(target))
	name := fmt.Sprintf("argos-web-resume-%s.cfg", hex.EncodeToString(sum[:])[:16])
	return filepath.Join(os.TempDir(), name)
}

// aggregateRuns merges the results of the phases of a scan.
func aggregateRuns(runs ...*runResult) *runResult {
	agg := &runResult{}
	for _, r := range runs {
		if r == nil {
			continue
		}
		agg.Duration += r.Duration
		agg.Sandboxed = agg.Sandboxed || r.Sandboxed
		agg.Stderr += r.Stderr
		if r.TimedOut {
			agg.TimedOut = true
		}
		if agg.ExitCode == 0 && r.ExitCode != 0 {
			agg.ExitCode = r.ExitCode
		}
	}
	return agg
}

// scanOutcome carries everything the result of a scan is built from.
type scanOutcome struct {
	target         string
	agg            *runResult
	passive        []Finding
	active         []Finding
	opts           nucleiScanOptions
	degraded       bool
	degradedReason string
	decision       guard.Decision
	breaker        *guard.Breaker
	wafDetected    bool
	wafVendor      string
	elapsed        time.Duration
}

// scanResult assembles the result of a scan: the findings of both phases
// reported separately, the traceability of the run and the verdict of the
// circuit breaker.
func scanResult(out scanOutcome) map[string]interface{} {
	res := baseResult("web.scan", out.target, out.agg)
	all := dedupeFindings(append(append([]Finding{}, out.passive...), out.active...))
	capped, truncated := capFindings(all)
	passive, _ := capFindings(out.passive)
	active, _ := capFindings(out.active)
	res["findings"] = findingsToMaps(capped)
	res["passive_findings"] = findingsToMaps(passive)
	res["active_findings"] = findingsToMaps(active)
	res["passive_count"] = len(out.passive)
	res["active_count"] = len(out.active)
	res["truncated"] = truncated
	res["rate_limit"] = out.opts.RateLimit
	res["concurrency"] = out.opts.Concurrency
	res["duration_ms"] = out.elapsed.Milliseconds()

	// nuclei does not expose a separate "executed" counter: with a single
	// target every template it loaded ran against it.
	templates, _ := nucleiTemplateStats(out.agg.Stderr)
	res["total_templates"] = templates
	res["executed_templates"] = templates
	res["matched_templates"] = matchedTemplateCount(capped)

	res["degraded"] = out.degraded
	if out.degraded {
		res["degraded_reason"] = out.degradedReason
	}
	res["waf_detected"] = out.wafDetected
	if out.wafDetected {
		res["waf_assessment"] = "fingerprint_observed"
	} else {
		res["waf_assessment"] = "inconclusive"
	}
	if out.wafVendor != "" {
		res["waf_vendor"] = out.wafVendor
	}
	if out.breaker != nil {
		res["breaker"] = map[string]interface{}{
			"action": out.decision.Action,
			"reason": out.decision.Reason,
			"stats":  out.breaker.Stats(),
		}
	}
	if out.decision.Action == guard.ActionAbort {
		res["status"] = "aborted"
		res["aborted"] = true
		res["abort_reason"] = out.decision.Reason
		res["summary"] = "scan aborted: " + out.decision.Reason
		return res
	}
	res["summary"] = fmt.Sprintf("%d vulnerabilities detected (%d passive, %d active)", len(capped), len(out.passive), len(out.active))
	return res
}

// abortedScanResult is the result of a scan that never started because the
// circuit breaker saw a degraded target.
func abortedScanResult(target string, decision guard.Decision, breaker *guard.Breaker, elapsed time.Duration) map[string]interface{} {
	res := baseResult("web.scan", target, &runResult{})
	res["status"] = "aborted"
	res["aborted"] = true
	res["abort_reason"] = decision.Reason
	res["findings"] = []map[string]any{}
	res["passive_findings"] = []map[string]any{}
	res["active_findings"] = []map[string]any{}
	res["passive_count"] = 0
	res["active_count"] = 0
	res["truncated"] = false
	res["duration_ms"] = elapsed.Milliseconds()
	res["degraded"] = false
	res["waf_detected"] = false
	res["waf_assessment"] = "not_run"
	if breaker != nil {
		res["breaker"] = map[string]interface{}{
			"action": decision.Action,
			"reason": decision.Reason,
			"stats":  breaker.Stats(),
		}
	}
	res["summary"] = "scan aborted: " + decision.Reason
	return res
}

// matchedTemplateCount counts the distinct templates that produced a finding.
func matchedTemplateCount(fs []Finding) int {
	seen := map[string]bool{}
	for _, f := range fs {
		if f.RuleID == "" {
			continue
		}
		seen[f.RuleID] = true
	}
	return len(seen)
}

// dedupeFindings removes the findings that both phases reported: the same
// rule against the same vector is one finding, not two.
func dedupeFindings(fs []Finding) []Finding {
	seen := map[string]bool{}
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		key := f.RuleID + "|" + f.Vector
		if f.RuleID == "" {
			key = f.Title + "|" + f.Vector
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// nucleiTemplateStats reads the statistics nuclei prints on stderr when it
// runs with -stats: {"templates":"11456","matched":"3",...}.
func nucleiTemplateStats(stderr string) (templates int, matched int) {
	for _, line := range lines(stderr) {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
			continue
		}
		value, ok := payload["templates"]
		if !ok {
			continue
		}
		templates = statInt(value)
		matched = statInt(payload["matched"])
	}
	return templates, matched
}

// statInt reads an integer out of a nuclei statistics value.
func statInt(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case string:
		number, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0
		}
		return number
	}
	return 0
}

func invalidParams(err error) *mcp.ErrorObj {
	return &mcp.ErrorObj{Code: -32602, Message: "Invalid parameters: " + err.Error()}
}

func clampTimeout(sec, def int) int {
	if sec <= 0 {
		return def
	}
	if sec > 300 {
		return 300
	}
	return sec
}
