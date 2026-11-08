package tools

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func createMockZipWithFiles(t *testing.T, targetZip string, files map[string]string) {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create entry %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write content: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}
	if err := os.WriteFile(targetZip, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("failed to save zip: %v", err)
	}
}

func TestDetectRuntimePython(t *testing.T) {
	path, err := DetectRuntime("python")
	if err != nil {
		t.Skip("Python 3 no instalado en host, skipping test")
	}
	if path == "" {
		t.Fatalf("expected python path, got empty")
	}
}

func TestDetectRuntimeUnknown(t *testing.T) {
	_, err := DetectRuntime("nonexistent_runtime_xyz")
	if err == nil {
		t.Fatalf("expected error for unknown runtime, got nil")
	}
}

func TestExtractTreeMockZip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")
	createMockZipWithFiles(t, zipPath, map[string]string{
		"repo-root/main.py":       "print('hello')",
		"repo-root/lib/helper.py": "def f(): pass",
	})

	destDir := filepath.Join(tmpDir, "extracted")
	err := extractTreeZip(zipPath, destDir)
	if err != nil {
		t.Fatalf("extractTreeZip failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "main.py")); err != nil {
		t.Fatalf("main.py was not extracted to destination root")
	}
	if _, err := os.Stat(filepath.Join(destDir, "lib", "helper.py")); err != nil {
		t.Fatalf("helper.py was not extracted to destination subfolder")
	}
}
