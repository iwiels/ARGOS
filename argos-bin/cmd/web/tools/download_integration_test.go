package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloader_EndToEnd(t *testing.T) {
	d := NewDownloader(t.TempDir())
	osName, archName := d.effectiveOS(), d.effectiveArch()
	bin := "tool"
	version := "1.0.0"
	archiveName := fmt.Sprintf("%s_%s_%s_%s.zip", bin, version, osName, archName)

	binFile := bin
	if osName == "windows" {
		binFile = bin + ".exe"
	}

	// build a real zip with the binary inside
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, _ := zw.Create(binFile)
	w.Write([]byte("#!/bin/sh\necho hi\n"))
	zw.Close()
	zipData := zipBuf.Bytes()

	hash := sha256.Sum256(zipData)
	checksumFile := fmt.Sprintf("%x  %s\n", hash[:], archiveName)

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/tool/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tag_name":"v1.0.0","assets":[`+
			`{"name":%q,"browser_download_url":%q},`+
			`{"name":%q,"browser_download_url":%q}]}`,
			archiveName, srvURL(r)+"/tool.zip",
			"tool_1.0.0_checksums.txt", srvURL(r)+"/checksums.txt")
	})
	mux.HandleFunc("/tool.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Write(zipData)
	})
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumFile))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// point the API client at the mock server and route the API base to it
	d.Client = srv.Client()
	oldAPI := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = oldAPI }()

	spec := &BinarySpec{Name: "tool", Repo: "acme/tool", Version: "v1.0.0", Bin: "tool", Archive: "zip"}
	path, installed, err := d.Ensure(context.Background(), spec)
	if err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	if !installed {
		t.Fatal("expected installed=true on first fetch")
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("binary not written: %v", err)
	}
	if filepath.Base(path) != binFile {
		t.Errorf("unexpected binary name: %s, want %s", filepath.Base(path), binFile)
	}

	// second call should be a cache hit
	path2, installed2, err := d.Ensure(context.Background(), spec)
	if err != nil || installed2 {
		t.Errorf("second Ensure: installed=%v err=%v", installed2, err)
	}
	if path2 != path {
		t.Errorf("cache path mismatch: %s vs %s", path2, path)
	}
}

func srvURL(r *http.Request) string {
	return "http://" + r.Host
}
