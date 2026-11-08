package paths

import (
	"path/filepath"
	"testing"
)

func TestResolveMemoryDir(t *testing.T) {
	home := t.TempDir()
	want := home + "/.argos/memory"

	if got := ResolveMemoryDir(home); got != want {
		t.Fatalf("ResolveMemoryDir(%q) = %q, want %q", home, got, want)
	}
}

func TestResolveMemoryDirEnvOverride(t *testing.T) {
	home := t.TempDir()
	override := filepath.Join(t.TempDir(), "custom-memory")
	t.Setenv(MemoryDirEnv, override)

	if got := ResolveMemoryDir(home); got != override {
		t.Fatalf("ResolveMemoryDir = %q, want %q", got, override)
	}
}
