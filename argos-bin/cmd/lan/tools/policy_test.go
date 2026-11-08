package tools

import (
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

func setLanTestScope(t *testing.T, cidrs ...string) {
	t.Helper()
	previous := lanScopeGuard
	guard, err := scope.New(scope.ScopeConfig{AllowedCIDRs: cidrs})
	if err != nil {
		t.Fatal(err)
	}
	lanScopeGuard = guard
	t.Cleanup(func() {
		guard.Close()
		lanScopeGuard = previous
	})
}

func TestValidateLanIPAllowsPrivateTargets(t *testing.T) {
	setLanTestScope(t, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.10.20"} {
		if _, errObj := validateLanIP(ip); errObj != nil {
			t.Fatalf("validateLanIP(%q) returned error: %s", ip, errObj.Message)
		}
	}
}

func TestValidateLanIPRejectsPublicTargetsByDefault(t *testing.T) {
	t.Setenv(allowPublicLanTargetsEnv, "")
	setLanTestScope(t, "8.8.8.8/32")
	if _, errObj := validateLanIP("8.8.8.8"); errObj == nil {
		t.Fatal("validateLanIP accepted public target without explicit override")
	}
}

func TestValidateLanIPAllowsPublicTargetsWithExplicitOverride(t *testing.T) {
	t.Setenv(allowPublicLanTargetsEnv, "1")
	setLanTestScope(t, "8.8.8.8/32")
	if _, errObj := validateLanIP("8.8.8.8"); errObj != nil {
		t.Fatalf("validateLanIP rejected public target with explicit override: %s", errObj.Message)
	}
}

func TestValidateLanCIDRRejectsPublicTargetsByDefault(t *testing.T) {
	t.Setenv(allowPublicLanTargetsEnv, "")
	setLanTestScope(t, "8.8.8.0/24")
	if _, errObj := validateLanCIDR("8.8.8.0/24"); errObj == nil {
		t.Fatal("validateLanCIDR accepted public target without explicit override")
	}
}
