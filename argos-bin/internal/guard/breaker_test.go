package guard

import (
	"strings"
	"testing"
)

func TestBreaker_AbortsOnServerErrorStorm(t *testing.T) {
	b := New(Options{})

	// 20 responses with 40% of 5xx: the target is degraded.
	var last Decision
	for i := 0; i < 20; i++ {
		status := 200
		if i%5 < 2 {
			status = 503
		}
		last = b.Observe(status, 120)
	}

	if last.Continue {
		t.Fatalf("the breaker must stop the scan, got %+v", last)
	}
	if last.Action != ActionAbort {
		t.Fatalf("action = %q, want %q", last.Action, ActionAbort)
	}
	if !strings.Contains(last.Reason, "server error rate") {
		t.Errorf("the abort reason must name the rule, got %q", last.Reason)
	}
	if !b.Aborted() {
		t.Error("the breaker must be latched after an abort")
	}
	stats := b.Stats()
	if stats.ServerErrors != 8 {
		t.Errorf("server errors = %d, want 8", stats.ServerErrors)
	}
	if stats.Samples != 20 {
		t.Errorf("samples = %d, want 20", stats.Samples)
	}
}

func TestBreaker_ContinuesOnHealthyTarget(t *testing.T) {
	b := New(Options{})

	for i := 0; i < 20; i++ {
		d := b.Observe(200, 90)
		if !d.Continue {
			t.Fatalf("the breaker must not stop a healthy target: %+v", d)
		}
		if d.Action != ActionNone {
			t.Fatalf("action = %q, want %q", d.Action, ActionNone)
		}
	}
	if b.Aborted() {
		t.Error("a healthy target must not latch the breaker")
	}
	if b.Stats().ServerErrorRate != 0 {
		t.Errorf("server error rate = %v, want 0", b.Stats().ServerErrorRate)
	}
}

func TestBreaker_DegradesOnWAF(t *testing.T) {
	b := New(Options{})

	b.ObserveWAFVendor("Cloudflare")

	d := b.Decision()
	if !d.Continue {
		t.Fatalf("a WAF must degrade the scan, not stop it: %+v", d)
	}
	if d.Action != ActionDegrade {
		t.Fatalf("action = %q, want %q", d.Action, ActionDegrade)
	}
	if !strings.Contains(d.Reason, "Cloudflare") {
		t.Errorf("the reason must name the WAF, got %q", d.Reason)
	}
	if !b.Stats().WAFDetected {
		t.Error("the WAF detection must be observable in the stats")
	}
}

func TestBreaker_LatencyDegradesThenAborts(t *testing.T) {
	b := New(Options{BaselineLatencyMs: 100})

	first := b.Observe(200, 500)
	if first.Action != ActionDegrade {
		t.Fatalf("the first slow response must degrade the scan, got %+v", first)
	}
	if !first.Continue {
		t.Fatal("a degraded scan still continues")
	}
	if !strings.Contains(first.Reason, "latency") {
		t.Errorf("the reason must name the rule, got %q", first.Reason)
	}

	second := b.Observe(200, 500)
	if second.Action != ActionDegrade {
		t.Fatalf("a persistent latency problem must keep degrading, got %+v", second)
	}

	third := b.Observe(200, 500)
	if third.Action != ActionAbort {
		t.Fatalf("a persistent latency problem must abort the scan, got %+v", third)
	}
	if third.Continue {
		t.Error("an aborted scan must not continue")
	}
}

func TestBreaker_LatchesAbort(t *testing.T) {
	b := New(Options{})

	for i := 0; i < 5; i++ {
		b.Observe(503, 100)
	}
	if !b.Aborted() {
		t.Fatal("the breaker must be latched after the abort")
	}

	// A healthy response does not rearm the breaker: the target is already
	// degraded and the same execution must not resume.
	d := b.Observe(200, 50)
	if d.Action != ActionAbort {
		t.Fatalf("action = %q, want %q after the latch", d.Action, ActionAbort)
	}
	if d.Continue {
		t.Error("a latched breaker must not continue")
	}
	if again := b.Decision(); again.Action != ActionAbort || again.Continue {
		t.Fatalf("the latched verdict must be stable: %+v", again)
	}
}

func TestBreaker_SingleErrorDoesNotAbort(t *testing.T) {
	b := New(Options{})

	d := b.Observe(500, 100)
	if !d.Continue {
		t.Fatalf("one server error must not stop the scan: %+v", d)
	}
}

func TestBreaker_LearnsBaselineWhenNotPinned(t *testing.T) {
	b := New(Options{})

	for i := 0; i < DefaultWindowSize; i++ {
		b.Observe(200, 100)
	}
	if stats := b.Stats(); stats.BaselineMs != 100 {
		t.Fatalf("baseline = %dms, want 100ms", stats.BaselineMs)
	}
	if d := b.Decision(); d.Action != ActionNone {
		t.Fatalf("a target at its baseline must not be degraded: %+v", d)
	}
}
