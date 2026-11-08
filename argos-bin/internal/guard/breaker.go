// Package guard implements the operational safety tripwires of an engagement.
//
// The circuit breaker is the piece that keeps Argos from denying service to
// the client: a scan that sees the target degrade (a 5xx storm, a latency
// collapse) has to stop or slow down before it takes the target down. It also
// owns the WAF fingerprint, because a WAF in front of the target is the first
// signal that the traffic is being metered and that the aggressive templates
// should be softened.
package guard

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
)

// Actions reported by a Decision.
const (
	// ActionNone means the scan continues untouched.
	ActionNone = ""
	// ActionDegrade means the scan continues with reduced aggressiveness.
	ActionDegrade = "degrade"
	// ActionAbort means the scan must stop.
	ActionAbort = "abort"
)

// Default thresholds of the breaker.
const (
	// DefaultWindowSize is how many recent responses the breaker keeps.
	DefaultWindowSize = 20
	// DefaultServerErrorRate is the ratio of 5xx responses that trips the
	// breaker. 30% is deliberately conservative: a target that answers one
	// request out of three with a server error is already in trouble, and a
	// scanner that keeps hammering it turns a bad moment into an outage.
	DefaultServerErrorRate = 0.30
	// DefaultLatencyMultiplier is how many times the baseline latency the
	// median of the window may reach before the breaker degrades the scan.
	DefaultLatencyMultiplier = 3.0
	// DefaultMinSamples is the minimum number of responses before a rate rule
	// may fire: without it a single 5xx would abort the scan.
	DefaultMinSamples = 5
	// DefaultLatencyAbortStreak is how many consecutive evaluations above the
	// latency threshold turn a degradation into an abort.
	DefaultLatencyAbortStreak = 3
)

// Options configures a Breaker. The zero value is valid: New fills every
// unset field with its default.
type Options struct {
	// WindowSize is how many recent responses the breaker keeps.
	WindowSize int
	// ServerErrorRate is the ratio of 5xx responses that aborts the scan.
	ServerErrorRate float64
	// LatencyMultiplier is how many times the baseline latency the median of
	// the window may reach before the scan is degraded (and then aborted).
	LatencyMultiplier float64
	// BaselineLatencyMs is the reference latency of the target. When it is
	// zero the breaker learns it from the first full window.
	BaselineLatencyMs int64
	// MinSamples is the minimum number of responses before a rate rule fires.
	MinSamples int
	// LatencyAbortStreak is how many consecutive evaluations above the
	// latency threshold abort the scan.
	LatencyAbortStreak int
}

// Decision is the verdict of the breaker for the next batch of requests.
type Decision struct {
	// Continue is false when the scan must stop.
	Continue bool `json:"continue"`
	// Reason explains the verdict in plain language.
	Reason string `json:"reason,omitempty"`
	// Action is "", "degrade" or "abort".
	Action string `json:"action,omitempty"`
}

// Stats is the observable state of the breaker.
type Stats struct {
	Samples         int     `json:"samples"`
	ServerErrors    int     `json:"server_errors"`
	ServerErrorRate float64 `json:"server_error_rate"`
	MedianLatencyMs int64   `json:"median_latency_ms"`
	BaselineMs      int64   `json:"baseline_latency_ms"`
	WAFDetected     bool    `json:"waf_detected"`
	WAFVendor       string  `json:"waf_vendor,omitempty"`
	Latched         bool    `json:"latched"`
}

// sample is one observed response.
type sample struct {
	status    int
	latencyMs int64
}

// Breaker decides whether a scan may continue, must soften, or must stop.
//
// It is not a global singleton on purpose: one breaker belongs to one scan
// session, so an aborted scan does not disable the next engagement.
type Breaker struct {
	mu   sync.Mutex
	opts Options

	window []sample

	wafDetected bool
	wafVendor   string

	latencyStreak int
	baselineMs    int64
	baselineSet   bool

	latched     bool
	latchReason string
}

// New creates a breaker with the given options. Unset options fall back to
// the package defaults and can be overridden by the operator through the
// ARGOS_BREAKER_* environment variables.
func New(opts Options) *Breaker {
	if opts.WindowSize <= 0 {
		opts.WindowSize = envInt("ARGOS_BREAKER_WINDOW_SIZE", DefaultWindowSize)
	}
	if opts.ServerErrorRate <= 0 {
		opts.ServerErrorRate = envFloat("ARGOS_BREAKER_SERVER_ERROR_RATE", DefaultServerErrorRate)
	}
	if opts.LatencyMultiplier <= 0 {
		opts.LatencyMultiplier = envFloat("ARGOS_BREAKER_LATENCY_MULTIPLIER", DefaultLatencyMultiplier)
	}
	if opts.BaselineLatencyMs <= 0 {
		opts.BaselineLatencyMs = int64(envInt("ARGOS_BREAKER_BASELINE_MS", 0))
	}
	if opts.MinSamples <= 0 {
		opts.MinSamples = envInt("ARGOS_BREAKER_MIN_SAMPLES", DefaultMinSamples)
	}
	if opts.LatencyAbortStreak <= 0 {
		opts.LatencyAbortStreak = envInt("ARGOS_BREAKER_LATENCY_ABORT_STREAK", DefaultLatencyAbortStreak)
	}
	if opts.MinSamples > opts.WindowSize {
		opts.MinSamples = opts.WindowSize
	}
	return &Breaker{
		opts:        opts,
		baselineMs:  opts.BaselineLatencyMs,
		baselineSet: opts.BaselineLatencyMs > 0,
	}
}

// Observe records a response and returns the verdict for the next batch.
//
// A status of 0 means the request never produced a response (transport
// error); it is recorded but it does not count towards the 5xx rate: a local
// network problem is not the target degrading.
func (b *Breaker) Observe(status int, latencyMs int64) Decision {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.window = append(b.window, sample{status: status, latencyMs: latencyMs})
	if len(b.window) > b.opts.WindowSize {
		b.window = b.window[len(b.window)-b.opts.WindowSize:]
	}
	b.learnBaseline()
	return b.evaluate(true)
}

// ObserveWAFVendor records the WAF vendor that was fingerprinted. An empty
// vendor means no WAF was detected.
func (b *Breaker) ObserveWAFVendor(vendor string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.wafDetected = vendor != ""
	b.wafVendor = vendor
}

// Decision returns the current verdict without recording anything.
func (b *Breaker) Decision() Decision {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.evaluate(false)
}

// Aborted reports whether the breaker already latched an abort.
func (b *Breaker) Aborted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.latched
}

// Stats returns the observable state of the breaker.
func (b *Breaker) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{
		Samples:         len(b.window),
		ServerErrors:    b.serverErrors(),
		ServerErrorRate: b.serverErrorRate(),
		MedianLatencyMs: b.medianLatency(),
		BaselineMs:      b.baselineMs,
		WAFDetected:     b.wafDetected,
		WAFVendor:       b.wafVendor,
		Latched:         b.latched,
	}
}

// evaluate applies the rules over the current window.
//
// The abort rules come first: a target that is already failing must not be
// softened, it must be left alone. The degradation rules come last: they only
// apply to a target that is still answering.
func (b *Breaker) evaluate(mutate bool) Decision {
	if b.latched {
		return Decision{Continue: false, Action: ActionAbort, Reason: b.latchReason}
	}

	// Rule 1: server error rate. More than a third of the recent responses
	// answering 5xx means the target is degraded; continuing would risk
	// denying service to the client.
	if rate := b.serverErrorRate(); len(b.window) >= b.opts.MinSamples && rate > b.opts.ServerErrorRate {
		reason := fmt.Sprintf(
			"server error rate %.0f%% over the last %d responses exceeds the %.0f%% threshold: the target is degraded and the scan was stopped to avoid denying service",
			rate*100, len(b.window), b.opts.ServerErrorRate*100,
		)
		if mutate {
			b.latch(reason)
		}
		return Decision{Continue: false, Action: ActionAbort, Reason: reason}
	}

	// Rule 2: latency. A target that suddenly answers 3x slower than its
	// baseline is saturating; the first sign softens the scan, a persistent
	// one stops it.
	if b.latencyExceeded() {
		if mutate {
			b.latencyStreak++
		}
		median := b.medianLatency()
		threshold := b.baselineMs * int64(b.opts.LatencyMultiplier)
		if b.latencyStreak >= b.opts.LatencyAbortStreak {
			reason := fmt.Sprintf(
				"median latency %dms exceeds %dx the %dms baseline over the last %d responses: the target is saturating and the scan was stopped",
				median, int(b.opts.LatencyMultiplier), b.baselineMs, len(b.window),
			)
			if mutate {
				b.latch(reason)
			}
			return Decision{Continue: false, Action: ActionAbort, Reason: reason}
		}
		return Decision{
			Continue: true,
			Action:   ActionDegrade,
			Reason: fmt.Sprintf(
				"median latency %dms exceeds %dx the %dms baseline: the scan was degraded (threshold %dms)",
				median, int(b.opts.LatencyMultiplier), b.baselineMs, threshold,
			),
		}
	}
	if mutate {
		b.latencyStreak = 0
	}

	// Rule 3: WAF. A WAF in front of the target means the traffic is being
	// metered and probably blocked: keep scanning, but softly.
	if b.wafDetected {
		return Decision{
			Continue: true,
			Action:   ActionDegrade,
			Reason:   b.wafReason(),
		}
	}

	return Decision{Continue: true}
}

// latch opens the breaker: once aborted, the same execution never resumes.
func (b *Breaker) latch(reason string) {
	if b.latched {
		return
	}
	b.latched = true
	b.latchReason = reason
}

// wafReason explains the degradation caused by a WAF.
func (b *Breaker) wafReason() string {
	if b.wafVendor != "" {
		return fmt.Sprintf("a WAF was detected in front of the target (%s): the scan was degraded (lower rate limit, no intrusive payloads)", b.wafVendor)
	}
	return "a WAF was detected in front of the target: the scan was degraded (lower rate limit, no intrusive payloads)"
}

// learnBaseline derives the reference latency from the first full window when
// the operator did not pin one.
func (b *Breaker) learnBaseline() {
	if b.baselineSet {
		return
	}
	if len(b.window) < b.opts.WindowSize {
		return
	}
	b.baselineMs = b.medianLatency()
	b.baselineSet = true
}

// latencyExceeded reports whether the median of the window is above the
// tolerated multiple of the baseline.
func (b *Breaker) latencyExceeded() bool {
	if !b.baselineSet || b.baselineMs <= 0 {
		return false
	}
	if len(b.window) == 0 {
		return false
	}
	return b.medianLatency() > b.baselineMs*int64(b.opts.LatencyMultiplier)
}

// serverErrors counts the 5xx responses of the window.
func (b *Breaker) serverErrors() int {
	count := 0
	for _, s := range b.window {
		if s.status >= 500 && s.status <= 599 {
			count++
		}
	}
	return count
}

// serverErrorRate is the ratio of 5xx responses over the window.
func (b *Breaker) serverErrorRate() float64 {
	if len(b.window) == 0 {
		return 0
	}
	return float64(b.serverErrors()) / float64(len(b.window))
}

// medianLatency is the median latency of the window.
func (b *Breaker) medianLatency() int64 {
	if len(b.window) == 0 {
		return 0
	}
	values := make([]int64, 0, len(b.window))
	for _, s := range b.window {
		values = append(values, s.latencyMs)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return values[mid]
	}
	return (values[mid-1] + values[mid]) / 2
}

// envInt reads a positive integer from the environment.
func envInt(name string, def int) int {
	raw := strings.TrimSpace(env.Get(name))
	if raw == "" {
		return def
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return def
	}
	return value
}

// envFloat reads a positive float from the environment.
func envFloat(name string, def float64) float64 {
	raw := strings.TrimSpace(env.Get(name))
	if raw == "" {
		return def
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 {
		return def
	}
	return value
}
