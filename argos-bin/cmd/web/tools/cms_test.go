package tools

import (
	"testing"
)

func TestCMSConditionalSkip(t *testing.T) {
	result, skip := evaluateCMSExecution("nginx, express", false)
	if !skip {
		t.Fatalf("expected skip for non-wordpress target")
	}
	if result["skip_reason"] == "" {
		t.Fatalf("expected skip_reason explaining technology mismatch")
	}
}

func TestCMSForceExecution(t *testing.T) {
	_, skip := evaluateCMSExecution("nginx", true)
	if skip {
		t.Fatalf("expected no skip when force is true")
	}
}
