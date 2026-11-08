package tools

import (
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

func TestSessionBreakerIsSharedByControllerSession(t *testing.T) {
	base := envWithScope(t, scope.ScopeConfig{AllowedCIDRs: []string{"127.0.0.0/8"}})
	snapshot := &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}}
	first, releaseFirst, errObj := scopedToolEnvironment(base, mcp.ToolContext{
		SessionID: "ses_breaker_shared",
		OperationID: "call_first",
		Scope: snapshot,
	})
	if errObj != nil {
		t.Fatal(errObj)
	}
	defer releaseFirst()
	second, releaseSecond, errObj := scopedToolEnvironment(base, mcp.ToolContext{
		SessionID: "ses_breaker_shared",
		OperationID: "call_second",
		Scope: snapshot,
	})
	if errObj != nil {
		t.Fatal(errObj)
	}
	defer releaseSecond()
	other, releaseOther, errObj := scopedToolEnvironment(base, mcp.ToolContext{
		SessionID: "ses_breaker_other",
		OperationID: "call_other",
		Scope: snapshot,
	})
	if errObj != nil {
		t.Fatal(errObj)
	}
	defer releaseOther()

	if SessionBreaker(first) != SessionBreaker(second) {
		t.Fatal("operations in one controller session received separate circuit breakers")
	}
	if SessionBreaker(first) == SessionBreaker(other) {
		t.Fatal("circuit breaker state leaked between controller sessions")
	}
}
