package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/iwiels/ARGOS/argos-bin/internal/env"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	toolsDirEnv          = "ARGOS_TOOLS_DIR"
	disableDownloadEnv   = "ARGOS_DISABLE_TOOL_DOWNLOAD"
	defaultDownloadLimit = 200 << 20 // 200MB archive cap
)

const (
	templatesVersionFile = ".version"
	templatesSHA256File  = ".sha256"
)

// githubAPI is the GitHub API base URL (var so tests can override it).
var githubAPI = "https://api.github.com"

// githubArchiveBase is the base URL for GitHub source archives and release
// assets (var so tests can override it).
var githubArchiveBase = "https://github.com"

// Downloader fetches and caches third-party binaries under Dir (~/.argos/tools).
//
// EXCEPTION TO THE SCOPE RULE: this client is intentionally NOT bound to the
// ScopeGuard. It talks to GitHub Releases to fetch the scanner binaries
// themselves — those hosts are not the engagement target and pinning them to
// the authorized scope would make the tooling uninstallable. It never carries
// engagement traffic, only vendor artifacts whose SHA-256 is verified before
// use.
type Downloader struct {
	Dir        string
	Client     *http.Client
	TargetOS   string
	TargetArch string
	mu         sync.Mutex
}

func (d *Downloader) effectiveOS() string {
	if d.TargetOS != "" {
		return d.TargetOS
	}
	if target, ok := defaultExecutor.(interface{ TargetOS() string }); ok {
		return target.TargetOS()
	}
	return runtime.GOOS
}

func (d *Downloader) effectiveArch() string {
	if d.TargetArch != "" {
		return d.TargetArch
	}
	if target, ok := defaultExecutor.(interface{ TargetArch() string }); ok {
		return target.TargetArch()
	}
	return runtime.GOARCH
}

func DefaultToolsDir() (string, error) {
	if d := env.Get(toolsDirEnv); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".argos", "tools"), nil
}

func NewDownloader(dir string) *Downloader {
	targetOS := runtime.GOOS
	targetArch := runtime.GOARCH
	if target, ok := defaultExecutor.(interface {
		TargetOS() string
		TargetArch() string
	}); ok {
		targetOS = target.TargetOS()
		targetArch = target.TargetArch()
	}
	return &Downloader{
		Dir:        dir,
		Client:     &http.Client{Timeout: 2 * time.Minute},
		TargetOS:   targetOS,
		TargetArch: targetArch,
	}
}

var naabuEnsureMu sync.Mutex

func EnsureNaabu(ctx context.Context) (string, bool, error) {
	dir, err := DefaultToolsDir()
	if err != nil {
		return "", false, err
	}

	specs := loadWebToolsConfig()
	var spec *BinarySpec
	for i := range specs {
		if specs[i].Name == "naabu" {
			spec = &specs[i]
			break
		}
	}
	if spec == nil {
		return "", false, fmt.Errorf("pinned Naabu specification is missing")
	}

	naabuEnsureMu.Lock()
	defer naabuEnsureMu.Unlock()
	return NewDownloader(dir).Ensure(ctx, spec)
}

// Ensure returns the path to a tool binary, downloading it on first use.
// installed reports whether the binary was fetched during this call.
func (d *Downloader) Ensure(ctx context.Context, spec *BinarySpec) (string, bool, error) {
	return d.ensureForTarget(ctx, spec, d.effectiveOS(), d.effectiveArch())
}

func unsupportedTargetError(spec *BinarySpec, goos, goarch string) error {
	for _, target := range spec.UnsupportedTargets {
		if target == goos+"/"+goarch {
			return fmt.Errorf("no %s/%s release asset for %s %s", goos, goarch, spec.Name, spec.Version)
		}
	}
	return nil
}

func (d *Downloader) ensureForTarget(ctx context.Context, spec *BinarySpec, goos, goarch string) (string, bool, error) {
	if err := unsupportedTargetError(spec, goos, goarch); err != nil {
		return "", false, err
	}
	if spec.Kind == "pip" {
		binPath, err := EnsureVenv(ctx, d.Dir, spec.Name, spec.Pkg)
		return binPath, false, err
	}
	if spec.Kind == "templates" {
		return "", false, fmt.Errorf("tool %q is a template set, not an executable", spec.Name)
	}

	binPath := filepath.Join(d.Dir, spec.Name, spec.TargetExecutableNameFor(goos))
	if fi, err := os.Stat(binPath); err == nil && fi.Size() > 0 {
		return binPath, false, nil
	}
	if env.Get(disableDownloadEnv) == "1" {
		return "", false, fmt.Errorf("tool %q is not installed and downloads are disabled (%s=1); install it at %s", spec.Name, disableDownloadEnv, binPath)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if fi, err := os.Stat(binPath); err == nil && fi.Size() > 0 {
		return binPath, false, nil
	}
	if err := d.install(ctx, spec); err != nil {
		return "", false, err
	}
	return binPath, true, nil
}

// ————— community template sets (nuclei-templates) —————

// templatesArchiveName returns the canonical archive file name published for a
// template release. It is the key used to look the digest up in the vendor
// checksums file.
func templatesArchiveName(spec *BinarySpec) string {
	return fmt.Sprintf("%s-%s.zip", spec.Name, strings.TrimPrefix(spec.Version, "v"))
}

// templatesArchiveURL returns the URL of the tagged source archive.
func templatesArchiveURL(spec *BinarySpec) string {
	return fmt.Sprintf("%s/%s/archive/refs/tags/%s.zip", githubArchiveBase, spec.Repo, spec.Version)
}

// templatesChecksumsURL returns the URL of the release asset holding the
// sha256 digests published by the template vendor.
func templatesChecksumsURL(spec *BinarySpec) string {
	asset := fmt.Sprintf("%s-%s_checksums.txt", spec.Name, strings.TrimPrefix(spec.Version, "v"))
	return fmt.Sprintf("%s/%s/releases/download/%s/%s", githubArchiveBase, spec.Repo, spec.Version, asset)
}

// EnsureTemplates makes the pinned community template set available under
// <toolsDir>/<name>/<version> and returns the directory to hand to nuclei via
// -templates. It is idempotent: when the pinned version is already installed
// the archive is not downloaded again and updated is false.
//
// The archive is verified against the pinned sha256 and, when the vendor
// publishes a checksums file for the tag, against that file too. Callers must
// treat an error as "templates unavailable" and fall back to the template set
// nuclei ships with.
func (d *Downloader) EnsureTemplates(ctx context.Context, spec *BinarySpec) (templatesDir string, version string, updated bool, err error) {
	if spec == nil {
		return "", "", false, fmt.Errorf("templates spec is required")
	}
	version = spec.Version
	base := filepath.Join(d.Dir, spec.Name)
	templatesDir = filepath.Join(base, version)

	d.mu.Lock()
	defer d.mu.Unlock()

	installed, err := templatesInstalled(templatesDir, version)
	if err != nil {
		return "", "", false, err
	}
	if installed {
		return templatesDir, version, false, nil
	}
	if env.Get(disableDownloadEnv) == "1" {
		return "", "", false, fmt.Errorf("templates %s are not installed and downloads are disabled (%s=1)", version, disableDownloadEnv)
	}

	archive, err := d.downloadTemplatesArchive(ctx, spec)
	if err != nil {
		return "", "", false, err
	}
	defer os.Remove(archive)

	sum, err := sha256File(archive)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot hash templates archive: %w", err)
	}
	if err := d.verifyTemplatesChecksum(ctx, spec, sum); err != nil {
		return "", "", false, err
	}
	if err := installTemplatesTree(archive, templatesDir); err != nil {
		return "", "", false, fmt.Errorf("cannot install templates: %w", err)
	}
	if err := os.WriteFile(filepath.Join(templatesDir, templatesSHA256File), []byte(sum), 0o644); err != nil {
		return "", "", false, fmt.Errorf("cannot write templates checksum marker: %w", err)
	}
	// the version marker is written last: its presence means the set is complete
	if err := os.WriteFile(filepath.Join(templatesDir, templatesVersionFile), []byte(version), 0o644); err != nil {
		return "", "", false, fmt.Errorf("cannot write templates version marker: %w", err)
	}
	return templatesDir, version, true, nil
}

// templatesInstalled reports whether the given templates directory already
// holds the requested version.
func templatesInstalled(dir, version string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, templatesVersionFile))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(string(data)) == version, nil
}

// TemplatesSHA256 returns the sha256 of the installed template archive, or an
// empty string when it was not recorded.
func TemplatesSHA256(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, templatesSHA256File))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// downloadTemplatesArchive fetches the tagged source archive into a temporary
// file and returns its path.
func (d *Downloader) downloadTemplatesArchive(ctx context.Context, spec *BinarySpec) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, templatesArchiveURL(spec), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "argos-web-mcp")
	resp, err := d.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot download templates for %s: %w", spec.Repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("templates download status %d for %s %s", resp.StatusCode, spec.Repo, spec.Version)
	}
	dir := filepath.Join(d.Dir, spec.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, "templates-*.zip")
	if err != nil {
		return "", err
	}
	path := tmp.Name()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, defaultDownloadLimit))
	tmp.Close()
	if err != nil {
		os.Remove(path)
		return "", err
	}
	if n >= defaultDownloadLimit {
		os.Remove(path)
		return "", fmt.Errorf("templates archive for %s exceeds size limit", spec.Name)
	}
	return path, nil
}

// verifyTemplatesChecksum validates the downloaded archive against the pinned
// digest and against the digests published by the vendor for that tag.
func (d *Downloader) verifyTemplatesChecksum(ctx context.Context, spec *BinarySpec, sum string) error {
	remote := ""
	if published, err := d.fetchTemplatesChecksum(ctx, spec); err != nil {
		log.Printf("argos-web: could not read published checksums for %s %s: %v", spec.Repo, spec.Version, err)
	} else {
		remote = published
	}
	if remote != "" && !strings.EqualFold(remote, sum) {
		return fmt.Errorf("sha256 mismatch for %s %s: got %s want %s", spec.Repo, spec.Version, sum, remote)
	}
	if spec.SHA256 != "" {
		if !strings.EqualFold(spec.SHA256, sum) {
			return fmt.Errorf("sha256 mismatch for %s %s: got %s want %s", spec.Repo, spec.Version, sum, spec.SHA256)
		}
		return nil
	}
	if remote == "" {
		return fmt.Errorf("no pinned sha256 for %s %s and no published checksums found", spec.Repo, spec.Version)
	}
	return nil
}

// fetchTemplatesChecksum returns the digest the vendor publishes for the
// template archive of the pinned tag.
func (d *Downloader) fetchTemplatesChecksum(ctx context.Context, spec *BinarySpec) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, templatesChecksumsURL(spec), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "argos-web-mcp")
	resp, err := d.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksums status %d for %s %s", resp.StatusCode, spec.Repo, spec.Version)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return checksumFor(templatesArchiveName(spec), string(data)), nil
}

// installTemplatesTree extracts the archive into destDir, replacing any
// previous partial installation.
func installTemplatesTree(archive, destDir string) error {
	staging, err := os.MkdirTemp(filepath.Dir(destDir), ".templates-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := extractTreeZip(archive, staging); err != nil {
		return err
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return err
	}
	if err := os.RemoveAll(destDir); err != nil {
		return err
	}
	return os.Rename(staging, destDir)
}

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type resolvedRelease struct {
	archiveName string
	archiveURL  string
	checksumURL string
	archiveType string // "zip" or "tar.gz" as resolved from the actual asset
}

func (d *Downloader) resolveRelease(ctx context.Context, spec *BinarySpec) (*resolvedRelease, error) {
	api := fmt.Sprintf("%s/repos/%s/releases/tags/%s", githubAPI, spec.Repo, spec.Version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "argos-web-mcp")
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach GitHub releases for %s: %w", spec.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("release %s %s not found", spec.Repo, spec.Version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API status %d for %s", resp.StatusCode, spec.Name)
	}
	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rel); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(rel.Assets))
	byName := make(map[string]string, len(rel.Assets))
	for _, a := range rel.Assets {
		names = append(names, a.Name)
		byName[a.Name] = a.URL
	}
	archiveName, err := selectArchiveAssetFor(names, byName, spec, d.effectiveOS(), d.effectiveArch())
	if err != nil {
		return nil, err
	}
	archiveType := spec.Archive
	if strings.HasSuffix(archiveName, ".zip") {
		archiveType = "zip"
	} else if strings.HasSuffix(archiveName, ".tar.gz") {
		archiveType = "tar.gz"
	}
	checksumName := pickChecksumAssetFor(names, archiveName)
	return &resolvedRelease{
		archiveName: archiveName,
		archiveURL:  byName[archiveName],
		checksumURL: byName[checksumName],
		archiveType: archiveType,
	}, nil
}

func selectArchiveAssetFor(names []string, byName map[string]string, spec *BinarySpec, goos, goarch string) (string, error) {
	for _, target := range spec.UnsupportedTargets {
		if target == goos+"/"+goarch {
			return "", fmt.Errorf("no %s/%s release asset for %s %s", goos, goarch, spec.Name, spec.Version)
		}
	}

	if spec.AssetTemplate == "" {
		archiveName := pickArchiveAsset(names, goos, goarch, spec.Archive)
		if archiveName == "" && spec.Kind == "source" {
			archiveName = pickSourceArchiveAsset(names, spec.Archive)
		}
		if archiveName == "" {
			return "", fmt.Errorf("no %s/%s release asset for %s %s", goos, goarch, spec.Name, spec.Version)
		}
		return archiveName, nil
	}

	if spec.AssetArch != "" && goarch != spec.AssetArch && goos != "darwin" {
		return "", fmt.Errorf("no %s/%s release asset for %s %s", goos, goarch, spec.Name, spec.Version)
	}
	token, ok := spec.AssetPlatforms[goos]
	if !ok {
		return "", fmt.Errorf("no %s release asset for %s %s", goos, spec.Name, spec.Version)
	}
	archiveName := strings.ReplaceAll(spec.AssetTemplate, "{platform}", token)
	if _, ok := byName[archiveName]; !ok {
		return "", fmt.Errorf("release asset %q not found for %s %s (%s/%s)", archiveName, spec.Repo, spec.Version, goos, goarch)
	}
	return archiveName, nil
}

var (
	osAliases = map[string][]string{
		"windows": {"windows", "win"},
		"linux":   {"linux"},
		"darwin":  {"darwin", "macos", "mac"},
	}
	archAliases = map[string][]string{
		"amd64": {"amd64", "x86_64"},
		"arm64": {"arm64", "aarch64"},
		"386":   {"386", "i386", "x86"},
	}
)

func aliasValues(m map[string][]string, key string) []string {
	if v, ok := m[key]; ok {
		return v
	}
	return []string{key}
}

// pickArchiveAsset selects the release asset for a given os/arch, preferring
// the spec's archive extension. It handles both underscore naming
// (projectdiscovery: nuclei_3.11.0_windows_amd64.zip) and hyphen naming
// (dalfox: dalfox-v3.2.0-windows-x86_64.tar.gz), with common os/arch aliases
// (x86_64==amd64, macos==darwin, ...). Pure helper, unit-testable.
func otherExt(ext string) string {
	if ext == "zip" {
		return "tar.gz"
	}
	return "zip"
}

func pickArchiveAsset(assets []string, osName, archName, ext string) string {
	// some tools publish per-OS formats (dalfox ships windows as zip but
	// linux/macos as tar.gz) — retry with the alternate extension if the
	// preferred one does not match any asset
	for _, e := range []string{ext, otherExt(ext)} {
		var suffixes []string
		for _, o := range aliasValues(osAliases, osName) {
			for _, a := range aliasValues(archAliases, archName) {
				suffixes = append(suffixes, "_"+o+"_"+a+"."+e)
				suffixes = append(suffixes, "-"+o+"-"+a+"."+e)
			}
		}
		for _, a := range assets {
			if strings.Contains(strings.ToLower(a), ".sha256") || strings.Contains(strings.ToLower(a), "checksum") {
				continue
			}
			for _, s := range suffixes {
				if strings.Contains(a, s) {
					return a
				}
			}
		}
		// loose fallback: any archive asset containing os and arch tokens
		for _, a := range assets {
			low := strings.ToLower(a)
			if !strings.HasSuffix(low, "."+e) || strings.Contains(low, ".sha256") || strings.Contains(low, "checksum") {
				continue
			}
			// prefer dynamically-linked builds over static/musl variants
			if strings.Contains(low, "musl") || strings.Contains(low, "static") {
				continue
			}
			osHit, archHit := false, false
			for _, o := range aliasValues(osAliases, osName) {
				if strings.Contains(low, o) {
					osHit = true
					break
				}
			}
			for _, ar := range aliasValues(archAliases, archName) {
				if strings.Contains(low, ar) {
					archHit = true
					break
				}
			}
			if osHit && archHit {
				return a
			}
		}
	}
	return ""
}

// pickChecksumAsset finds the checksums file regardless of naming convention.
func pickChecksumAsset(assets []string) string {
	for _, a := range assets {
		if strings.Contains(strings.ToLower(a), "checksum") {
			return a
		}
	}
	return ""
}

// pickChecksumAssetFor finds the checksum file of a specific archive.
//
// A release that publishes one digest per platform (the CodeQL CLI ships
// codeql-<platform>.zip.checksum.txt for each archive) needs the digest
// that names the archive that was picked: the first checksum file of the
// release would be the one of another platform.
func pickChecksumAssetFor(assets []string, archiveName string) string {
	if archiveName != "" {
		lowered := strings.ToLower(archiveName)
		for _, a := range assets {
			low := strings.ToLower(a)
			if !strings.Contains(low, "checksum") && !strings.Contains(low, ".sha256") {
				continue
			}
			if strings.Contains(low, lowered) {
				return a
			}
		}
	}
	return pickChecksumAsset(assets)
}

func (d *Downloader) install(ctx context.Context, spec *BinarySpec) error {
	dir := filepath.Join(d.Dir, spec.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	rel, err := d.resolveRelease(ctx, spec)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "download-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.archiveURL, nil)
	if err != nil {
		tmp.Close()
		return err
	}
	req.Header.Set("User-Agent", "argos-web-mcp")
	resp, err := d.archiveClient(spec).Do(req)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("download failed for %s: %w", spec.Name, err)
	}
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		resp.Body.Close()
		return fmt.Errorf("download status %d for %s", resp.StatusCode, spec.Name)
	}
	limit := spec.downloadLimit()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, limit))
	resp.Body.Close()
	tmp.Close()
	if err != nil {
		return err
	}
	if n >= limit {
		return fmt.Errorf("archive for %s exceeds size limit", spec.Name)
	}

	if rel.checksumURL != "" {
		if err := d.verifyChecksum(ctx, tmpPath, rel.archiveName, rel.checksumURL, spec.RequireChecksum); err != nil {
			return fmt.Errorf("checksum verification failed for %s: %w", spec.Name, err)
		}
	}

	if spec.Kind == "source" {
		if rel.archiveType == "zip" {
			return extractTreeZip(tmpPath, dir)
		}
		return extractTreeTarGz(tmpPath, dir)
	}
	if spec.Kind == "bundle" {
		return installBundleTree(tmpPath, rel.archiveType, dir)
	}

	return extractArchive(tmpPath, rel.archiveType, spec, dir)
}

// archiveClient returns the client that fetches the archive of a spec.
//
// The default client has a two minute timeout, which is enough for the
// small scanners but not for a bundle of hundreds of megabytes: the CodeQL
// CLI ships 377MB on Windows, 499MB on Linux and 1.1GB on macOS.
func (d *Downloader) archiveClient(spec *BinarySpec) *http.Client {
	if d.Client == nil {
		return http.DefaultClient
	}
	if spec != nil && spec.downloadLimit() > defaultDownloadLimit {
		return &http.Client{Timeout: 30 * time.Minute}
	}
	return d.Client
}

// installBundleTree extracts a self-contained tool bundle.
//
// The bundle is a tree, not a single executable: the launcher needs the
// sibling directories (extractor packs, the bundled JRE, the query packs)
// next to it. The extraction goes through a staging directory so a failed
// download never leaves a half-installed bundle behind.
func installBundleTree(archivePath, archiveType, destDir string) error {
	staging, err := os.MkdirTemp(filepath.Dir(destDir), ".bundle-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if archiveType == "zip" {
		if err := extractTreeZip(archivePath, staging); err != nil {
			return fmt.Errorf("cannot extract bundle: %w", err)
		}
	} else {
		if err := extractTreeTarGz(archivePath, staging); err != nil {
			return fmt.Errorf("cannot extract bundle: %w", err)
		}
	}
	if err := os.RemoveAll(destDir); err != nil {
		return err
	}
	return os.Rename(staging, destDir)
}

func (d *Downloader) verifyChecksum(ctx context.Context, filePath, archiveName, checksumURL string, required bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "argos-web-mcp")
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	expected := checksumFor(archiveName, string(data))
	if expected == "" {
		if required {
			// the vendor publishes a digest for this asset: a file we cannot
			// read means the release changed shape, not that the archive can
			// be trusted blindly.
			return fmt.Errorf("no sha256 digest found for %s", archiveName)
		}
		return nil // unknown checksum format — best effort skip
	}
	sum, err := sha256File(filePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, expected) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", sum, expected)
	}
	return nil
}

func checksumFor(archiveName, content string) string {
	var loneHex string
	count := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		for _, f := range fields {
			if len(f) != 64 || !isHex(f) {
				continue
			}
			count++
			for _, other := range fields {
				if other != f && strings.Contains(other, archiveName) {
					return strings.ToLower(f)
				}
			}
			if loneHex == "" {
				loneHex = strings.ToLower(f)
			}
		}
	}
	// only trust a lone hash when the file contains exactly one entry
	if count == 1 {
		return loneHex
	}
	return ""
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractArchive(archivePath, archiveType string, spec *BinarySpec, dest string) error {
	var entries []archiveEntry
	var err error
	if archiveType == "zip" {
		entries, err = readZipEntries(archivePath)
	} else {
		entries, err = readTarGzEntries(archivePath)
	}
	if err != nil {
		return err
	}
	var target archiveEntry
	for _, e := range entries {
		if isTargetBinary(e.name, spec.Bin) {
			target = e
			break
		}
	}
	if target.name == "" {
		return fmt.Errorf("binary %q not found inside %s archive", spec.Bin, archivePath)
	}
	return writeFile(filepath.Join(dest, target.name), target.data)
}

type archiveEntry struct {
	name string
	data []byte
}

func isTargetBinary(base, bin string) bool {
	if base == bin || base == bin+".exe" {
		return true
	}
	return strings.HasPrefix(base, bin) && !strings.Contains(base, ".")
}

func readZipEntries(path string) ([]archiveEntry, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var entries []archiveEntry
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, defaultDownloadLimit))
		rc.Close()
		if err != nil {
			return nil, err
		}
		entries = append(entries, archiveEntry{name: filepath.Base(f.Name), data: data})
	}
	return entries, nil
}

func readTarGzEntries(path string) ([]archiveEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var entries []archiveEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, defaultDownloadLimit))
		if err != nil {
			return nil, err
		}
		entries = append(entries, archiveEntry{name: filepath.Base(hdr.Name), data: data})
	}
	return entries, nil
}

func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bin-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

func pickSourceArchiveAsset(assets []string, ext string) string {
	for _, e := range []string{ext, otherExt(ext)} {
		for _, a := range assets {
			low := strings.ToLower(a)
			if strings.Contains(low, ".sha256") || strings.Contains(low, "checksum") || strings.Contains(low, ".asc") || strings.Contains(low, ".sig") {
				continue
			}
			if strings.HasSuffix(low, "."+e) {
				return a
			}
		}
	}
	return ""
}

func extractTreeZip(archivePath, destDir string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	var commonPrefix string
	first := true
	for _, f := range zr.File {
		cleanName := strings.TrimPrefix(filepath.ToSlash(f.Name), "/")
		parts := strings.Split(cleanName, "/")
		if len(parts) > 1 {
			top := parts[0]
			if first {
				commonPrefix = top
				first = false
			} else if commonPrefix != "" && commonPrefix != top {
				commonPrefix = ""
			}
		} else if !f.FileInfo().IsDir() && cleanName != "" {
			commonPrefix = ""
			first = false
		}
	}

	for _, f := range zr.File {
		cleanName := strings.TrimPrefix(filepath.ToSlash(f.Name), "/")
		if cleanName == "" {
			continue
		}
		if commonPrefix != "" {
			if cleanName == commonPrefix {
				continue
			}
			if strings.HasPrefix(cleanName, commonPrefix+"/") {
				cleanName = strings.TrimPrefix(cleanName, commonPrefix+"/")
			}
		}
		if cleanName == "" {
			continue
		}

		targetPath := filepath.Join(destDir, filepath.FromSlash(cleanName))
		rel, err := filepath.Rel(destDir, targetPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode()|0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		rc.Close()
		outErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if outErr != nil {
			return outErr
		}
	}
	return nil
}

func extractTreeTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	var commonPrefix string
	first := true
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		cleanName := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "/")
		parts := strings.Split(cleanName, "/")
		if len(parts) > 1 {
			top := parts[0]
			if first {
				commonPrefix = top
				first = false
			} else if commonPrefix != "" && commonPrefix != top {
				commonPrefix = ""
			}
		} else if hdr.Typeflag != tar.TypeDir && cleanName != "" {
			commonPrefix = ""
			first = false
		}
	}
	gz.Close()
	f.Close()

	f2, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f2.Close()
	gz2, err := gzip.NewReader(f2)
	if err != nil {
		return err
	}
	defer gz2.Close()
	tr2 := tar.NewReader(gz2)

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	for {
		hdr, err := tr2.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		cleanName := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "/")
		if cleanName == "" {
			continue
		}
		if commonPrefix != "" {
			if cleanName == commonPrefix {
				continue
			}
			if strings.HasPrefix(cleanName, commonPrefix+"/") {
				cleanName = strings.TrimPrefix(cleanName, commonPrefix+"/")
			}
		}
		if cleanName == "" {
			continue
		}

		targetPath := filepath.Join(destDir, filepath.FromSlash(cleanName))
		rel, err := filepath.Rel(destDir, targetPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("illegal file path in tar: %s", hdr.Name)
		}

		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}

		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)|0o755)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr2)
		outErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if outErr != nil {
			return outErr
		}
	}
	return nil
}
