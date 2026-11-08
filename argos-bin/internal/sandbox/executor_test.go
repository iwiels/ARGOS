package sandbox

import (
	"context"
	"strings"
	"testing"
)

func TestSelectExecutorFallback(t *testing.T) {
	exec := DefaultExecutor()
	if exec == nil {
		t.Fatalf("DefaultExecutor must never return nil")
	}
}

func TestDockerExecutorBuildArgs(t *testing.T) {
	image := "ghcr.io/argos-auditor/scanner@sha256:" + strings.Repeat("a", 64)
	args, err := buildDockerArgs(CommandSpec{
		Path:        "/opt/argos/tools/nuclei",
		Args:        []string{"-target", "http://example.com"},
		Dir:         t.TempDir(),
		MemoryLimit: "2g",
		NetworkMode: "none",
	}, image)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"--network=none", "--memory=2g", "--cpus=2", "--user=65532:65532", "--cap-drop=ALL", image} {
		if !strings.Contains(joined, required) {
			t.Errorf("expected %q in Docker arguments: %s", required, joined)
		}
	}
}

func TestDockerExecutorRejectsWhenUnavailable(t *testing.T) {
	for _, strict := range []bool{true, false} {
		d := &DockerExecutor{dockerAvailable: false}
		result, err := d.Execute(context.Background(), CommandSpec{Path: "nuclei", Strict: strict})
		if err == nil || !strings.Contains(err.Error(), "Docker is required") || result != nil {
			t.Fatalf("unavailable Docker must fail closed (strict=%v): result=%+v, err=%v", strict, result, err)
		}
	}
}
