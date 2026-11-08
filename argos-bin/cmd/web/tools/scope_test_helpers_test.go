package tools

import (
	"context"
	"net"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

type fixedTestResolver struct {
	ips []net.IP
}

func (r fixedTestResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return r.ips, nil
}

func newTestWebScope(t *testing.T, config scope.ScopeConfig) *scope.ScopeGuard {
	t.Helper()
	guard, err := scope.New(config)
	if err != nil {
		t.Fatal(err)
	}
	guard.SetResolver(fixedTestResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}})
	t.Cleanup(guard.Close)
	return guard
}
