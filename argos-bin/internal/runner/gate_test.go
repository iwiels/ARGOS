package runner

import (
	"testing"
	"time"
)

func TestEvaluateGateFlagsOpenFindingAtThreshold(t *testing.T) {
	findings := []Finding{{ID: "finding-1", Severity: "high", CaseID: "case-open"}}
	cases := []FindingCase{{ID: "case-open", Status: "open"}}

	result := EvaluateGate(findings, cases, "high", time.UnixMilli(1_800_000_000_000))

	if !result.Failed {
		t.Fatal("an open high-severity finding must fail the high threshold")
	}
	if result.MatchingFindings != 1 {
		t.Fatalf("got %d matching findings, want 1", result.MatchingFindings)
	}
}

func TestEvaluateGateExcludesRemediatedAndUnexpiredAcceptedRisk(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	findings := []Finding{
		{ID: "finding-fixed", Severity: "critical", CaseID: "case-fixed"},
		{ID: "finding-risk", Severity: "critical", CaseID: "case-risk"},
	}
	cases := []FindingCase{
		{ID: "case-fixed", Status: "remediated"},
		{ID: "case-risk", Status: "accepted-risk", AcceptedRiskUntil: int64Ptr(now.Add(time.Hour).UnixMilli())},
	}

	result := EvaluateGate(findings, cases, "high", now)

	if result.Failed || result.MatchingFindings != 0 {
		t.Fatalf("resolved cases must not fail the gate: %+v", result)
	}
}

func int64Ptr(value int64) *int64 {
	return &value
}
