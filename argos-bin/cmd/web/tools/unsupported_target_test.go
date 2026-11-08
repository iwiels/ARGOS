package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureRejectsCachedBinaryForUnsupportedTarget(t *testing.T) {
	dir := t.TempDir()
	spec := &BinarySpec{
		Name:               "naabu",
		Version:            "v2.3.1",
		Bin:                "naabu",
		Archive:            "zip",
		Kind:               "binary",
		UnsupportedTargets: []string{"linux/arm64"},
	}
	binaryPath := filepath.Join(dir, spec.Name, spec.TargetExecutableNameFor("linux"))
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("cached binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, _, err := NewDownloader(dir).ensureForTarget(context.Background(), spec, "linux", "arm64")
	if err == nil || !strings.Contains(err.Error(), "no linux/arm64 release asset") {
		t.Fatalf("Ensure() error = %v, want unsupported linux/arm64 target despite cached binary", err)
	}
}
