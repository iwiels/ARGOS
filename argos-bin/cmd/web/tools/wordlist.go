package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
)

const (
	// seclistsRepo is the upstream wordlist repository.
	seclistsRepo = "danielmiessler/SecLists"
	// seclistsVersion pins the revision every wordlist is fetched from.
	seclistsVersion = "2026.1"
	// wordlistCacheDir is the subdirectory of the tools dir that holds the
	// fetched wordlists.
	wordlistCacheDir = "wordlists"
	// defaultWordlistTTLDays is the age after which a cached wordlist is
	// re-verified against its pinned checksum.
	defaultWordlistTTLDays = 30
	// maxWordlistSize caps a wordlist download (the biggest one is ~1.6MB).
	maxWordlistSize = 64 << 20
)

// rawGitHubBase serves the pinned files (var so tests can override it).
var rawGitHubBase = "https://raw.githubusercontent.com"

// Where a resolved wordlist comes from. The value is reported as
// "wordlist_source" so a scan always states which list it ran with.
const (
	wordlistSourceDownloaded = "downloaded" // fetched from the pinned upstream
	wordlistSourceCached     = "cached"     // already present in the cache
	wordlistSourceBundled    = "bundled"    // offline fallback shipped with Argos
)

// Wordlist profiles.
const (
	wordlistKindDirs   = "dirs"
	wordlistKindParams = "params"
	wordlistKindAPI    = "api"
	wordlistKindDNS    = "dns"
	wordlistKindHosts  = "hosts"
	wordlistKindBypass = "bypass"
)

// WordlistSpec describes a wordlist fetched on demand from a pinned
// upstream revision. The SHA-256 pin covers the file content, so a
// tampered or truncated download is rejected before it reaches a scanner.
type WordlistSpec struct {
	Name    string // "raft-large-words"
	Repo    string // "danielmiessler/SecLists"
	Path    string // "Discovery/Web-Content/raft-large-words.txt"
	Version string // tag of the repo
	SHA256  string // pin of the file content
	Lines   int
	Kind    string // "dirs" | "params" | "api" | "dns" | "hosts" | "bypass"

	// Source tells where the resolved file came from: "downloaded",
	// "cached" or "bundled". It is only set on the spec returned by
	// EnsureWordlist, never on the registry entries.
	Source string
}

// wordlistRegistry is the catalogue of wordlists Argos can fetch on
// demand. The digests are the sha256 of the files published in the pinned
// tag, computed over the raw bytes GitHub serves for that revision.
var wordlistRegistry = []WordlistSpec{
	{
		Name:    "raft-large-words",
		Repo:    seclistsRepo,
		Path:    "Discovery/Web-Content/raft-large-words.txt",
		Version: seclistsVersion,
		SHA256:  "0d51eae9b3a8dd56cbba37a42c8baa3b1c4b811319c8c5e0628c35db585fdae6",
		Lines:   119600,
		Kind:    wordlistKindDirs,
	},
	{
		Name:    "raft-small-words",
		Repo:    seclistsRepo,
		Path:    "Discovery/Web-Content/raft-small-words.txt",
		Version: seclistsVersion,
		SHA256:  "1aadf7dafde5ca68f5e5160c9206f7be6f6fc701775cdea30ba01bbb6d8db8ad",
		Lines:   43007,
		Kind:    wordlistKindDirs,
	},
	{
		Name:    "common",
		Repo:    seclistsRepo,
		Path:    "Discovery/Web-Content/common.txt",
		Version: seclistsVersion,
		SHA256:  "fc320bacd30d93f5080029912b93667cd739401f81634579a7125fc0c027e6d5",
		Lines:   4751,
		Kind:    wordlistKindDirs,
	},
	{
		Name:    "api-endpoints",
		Repo:    seclistsRepo,
		Path:    "Discovery/Web-Content/api/api-endpoints.txt",
		Version: seclistsVersion,
		SHA256:  "001a97bdab2d0cd787546ca3c543c01280fe6539b3337521aabfc6c0ea0703b1",
		Lines:   285,
		Kind:    wordlistKindAPI,
	},
	{
		Name:    "param-names",
		Repo:    seclistsRepo,
		Path:    "Discovery/Web-Content/burp-parameter-names.txt",
		Version: seclistsVersion,
		SHA256:  "91f7e457415ffd0e4278d13887804036b62240a135a022a6fd6e831a7151899f",
		Lines:   6453,
		Kind:    wordlistKindParams,
	},
	{
		Name:    "dns",
		Repo:    seclistsRepo,
		Path:    "Discovery/DNS/namelist.txt",
		Version: seclistsVersion,
		SHA256:  "e51bd258dfc74f8f519bc8c18a4494e331e7679a83ebca8f48c5cfaf68768ea0",
		Lines:   151265,
		Kind:    wordlistKindDNS,
	},
	{
		Name:    "bypass",
		Repo:    seclistsRepo,
		Path:    "Fuzzing/login_bypass.txt",
		Version: seclistsVersion,
		SHA256:  "c991cd49d454766f529583ec0b0bedf552652509a0494667d31ac78423593214",
		Lines:   896,
		Kind:    wordlistKindBypass,
	},
}

// wordlistAliases maps the profile names the tools accept onto a concrete
// wordlist of the registry.
var wordlistAliases = map[string]string{
	"dirs":      "raft-large-words",
	"dir":       "raft-large-words",
	"paths":     "raft-large-words",
	"big":       "raft-large-words",
	"large":     "raft-large-words",
	"small":     "raft-small-words",
	"fast":      "raft-small-words",
	"common":    "common",
	"api":       "api-endpoints",
	"endpoints": "api-endpoints",
	"params":    "param-names",
	"param":     "param-names",
	"dns":       "dns",
	"hosts":     "dns",
	"bypass":    "bypass",
}

// ResolveWordlist maps a wordlist name or profile alias onto its registry
// spec. It reports false when the name is unknown.
func ResolveWordlist(name string) (WordlistSpec, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return WordlistSpec{}, false
	}
	if target, ok := wordlistAliases[key]; ok {
		key = target
	}
	for _, spec := range wordlistRegistry {
		if spec.Name == key {
			return spec, true
		}
	}
	return WordlistSpec{}, false
}

// AvailableWordlists returns the catalogue metadata: one entry per
// wordlist Argos can fetch, with its kind, size and checksum pin.
func AvailableWordlists() []WordlistSpec {
	out := make([]WordlistSpec, len(wordlistRegistry))
	copy(out, wordlistRegistry)
	return out
}

// WordlistNames returns the registry names, for error messages and the
// catalogue tool.
func WordlistNames() []string {
	out := make([]string, 0, len(wordlistRegistry))
	for _, spec := range wordlistRegistry {
		out = append(out, spec.Name)
	}
	return out
}

// WordlistProfiles returns the accepted profile aliases and the wordlist
// each one resolves to.
func WordlistProfiles() map[string]string {
	out := make(map[string]string, len(wordlistAliases))
	for alias, target := range wordlistAliases {
		out[alias] = target
	}
	return out
}

// wordlistCachePath returns the on-disk location of a wordlist inside the
// tools dir. The version is part of the name so a new pin never collides
// with the file of a previous revision.
func wordlistCachePath(toolsDir string, spec WordlistSpec) string {
	return filepath.Join(toolsDir, wordlistCacheDir, spec.Name+"-"+spec.Version+".txt")
}

// wordlistToolsDir returns the directory that holds the wordlist cache.
func wordlistToolsDir(env *Env) string {
	if env != nil && env.Downloader != nil && env.Downloader.Dir != "" {
		return env.Downloader.Dir
	}
	dir, err := DefaultToolsDir()
	if err != nil {
		return ""
	}
	return dir
}

// wordlistTTLDays returns the age after which a cached wordlist is
// re-verified against its pinned checksum.
func wordlistTTLDays() int {
	raw := env.Get("ARGOS_WORDLIST_TTL_DAYS")
	if raw == "" {
		return defaultWordlistTTLDays
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return defaultWordlistTTLDays
	}
	return n
}

// EnsureWordlist resolves a wordlist profile into a file on disk,
// downloading it from the pinned upstream revision the first time it is
// needed. It falls back to the bundled list when the network is
// unavailable, and the returned spec states which source was used.
func EnsureWordlist(ctx context.Context, name string) (string, WordlistSpec, error) {
	dir, err := DefaultToolsDir()
	if err != nil {
		return "", WordlistSpec{}, fmt.Errorf("cannot resolve the tools directory: %w", err)
	}
	return EnsureWordlistIn(ctx, dir, name)
}

// EnsureWordlistIn is EnsureWordlist with an explicit tools directory.
func EnsureWordlistIn(ctx context.Context, toolsDir, name string) (string, WordlistSpec, error) {
	spec, ok := ResolveWordlist(name)
	if !ok {
		return "", WordlistSpec{}, fmt.Errorf("unknown wordlist %q: available %s", name, strings.Join(WordlistNames(), ", "))
	}
	path, source, err := fetchWordlist(ctx, toolsDir, spec)
	if err == nil {
		spec.Source = source
		return path, spec, nil
	}
	// Offline degradation: a missing or tampered download must not abort
	// the scan. The bundled list is used instead and the caller declares
	// it through the "bundled" source.
	log.Printf("argos-web: the wordlist %q is unavailable (%v); falling back to the bundled list", spec.Name, err)
	fbPath, fbSpec, fbErr := bundledWordlist(toolsDir, spec.Kind)
	if fbErr != nil {
		return "", spec, fmt.Errorf("cannot prepare the wordlist %q: %w", spec.Name, err)
	}
	return fbPath, fbSpec, nil
}

// fetchWordlist returns the cached wordlist, downloading it when it
// is missing or when its cached copy is older than the TTL and no longer
// matches the pinned checksum.
func fetchWordlist(ctx context.Context, toolsDir string, spec WordlistSpec) (string, string, error) {
	path := wordlistCachePath(toolsDir, spec)
	fi, err := os.Stat(path)
	switch {
	case err == nil && fi.Size() > 0:
		if !wordlistStale(fi) {
			return path, wordlistSourceCached, nil
		}
		// The cached copy aged out: re-verify it against the pin before
		// trusting it again, and only re-download when it does not match.
		if spec.SHA256 != "" {
			if sum, err := sha256File(path); err == nil && strings.EqualFold(sum, spec.SHA256) {
				touchFile(path)
				return path, wordlistSourceCached, nil
			}
		}
	case err != nil && !os.IsNotExist(err):
		return "", "", fmt.Errorf("cannot stat the wordlist cache: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", fmt.Errorf("cannot create the wordlist cache: %w", err)
	}
	if err := downloadWordlist(ctx, spec, path); err != nil {
		return "", "", err
	}
	return path, wordlistSourceDownloaded, nil
}

// wordlistStale reports whether the cached file is older than the TTL and
// must be re-verified.
func wordlistStale(fi os.FileInfo) bool {
	ttl := time.Duration(wordlistTTLDays()) * 24 * time.Hour
	if ttl <= 0 {
		return true
	}
	return time.Since(fi.ModTime()) > ttl
}

// touchFile refreshes the modification time of a cached wordlist so the
// TTL counts from the last verification.
func touchFile(path string) {
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		log.Printf("argos-web: cannot refresh the timestamp of the wordlist %s: %v", path, err)
	}
}

// downloadWordlist fetches the pinned file and installs it in the cache
// only when it matches the pinned checksum.
//
// The request goes through the shared Downloader client: like the binary
// downloads, a wordlist is a vendor artifact and never engagement
// traffic, so it must not go through the scope-bound client.
func downloadWordlist(ctx context.Context, spec WordlistSpec, dest string) error {
	url := fmt.Sprintf("%s/%s/%s/%s", rawGitHubBase, spec.Repo, spec.Version, spec.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "argos-web-mcp")
	resp, err := NewDownloader(filepath.Dir(dest)).Client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot download the wordlist %s: %w", spec.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wordlist download status %d for %s/%s@%s", resp.StatusCode, spec.Repo, spec.Path, spec.Version)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".wordlist-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxWordlistSize))
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("the downloaded wordlist %s is empty", spec.Name)
	}
	if n >= maxWordlistSize {
		return fmt.Errorf("the wordlist %s exceeds the size limit", spec.Name)
	}
	if spec.SHA256 != "" {
		sum, err := sha256File(tmpPath)
		if err != nil {
			return err
		}
		if !strings.EqualFold(sum, spec.SHA256) {
			return fmt.Errorf("sha256 mismatch for the wordlist %s: got %s want %s", spec.Name, sum, spec.SHA256)
		}
	} else {
		// A missing pin means the download was only checked over HTTP.
		// Invented digests would be worse than an honest gap.
		log.Printf("argos-web: the wordlist %s has no pinned sha256; the download was only verified over HTTP", spec.Name)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("cannot install the wordlist %s: %w", spec.Name, err)
	}
	return nil
}

// bundledWordlist materializes the offline fallback for a profile: the
// common.txt shipped with the auditoria-web skill when the config dir
// exposes it, and the embedded list otherwise. The parameter profile has
// no bundled text file, so it falls back to the embedded parameter names.
func bundledWordlist(toolsDir, kind string) (string, WordlistSpec, error) {
	if kind == wordlistKindParams {
		path, err := writeBundledList(toolsDir, "params", paramNames)
		if err != nil {
			return "", WordlistSpec{}, err
		}
		return path, WordlistSpec{
			Name:   "bundled-params",
			Kind:   wordlistKindParams,
			Lines:  len(paramNames),
			Source: wordlistSourceBundled,
		}, nil
	}
	if p := wordlistPath(); p != "" {
		entries, _ := countWordlistEntries(p)
		return p, WordlistSpec{
			Name:   "common",
			Kind:   wordlistKindDirs,
			Lines:  entries,
			Source: wordlistSourceBundled,
		}, nil
	}
	path, err := writeBundledList(toolsDir, "common", fallbackWordlist)
	if err != nil {
		return "", WordlistSpec{}, err
	}
	return path, WordlistSpec{
		Name:   "bundled-common",
		Kind:   wordlistKindDirs,
		Lines:  len(fallbackWordlist),
		Source: wordlistSourceBundled,
	}, nil
}

// writeBundledList stores an embedded list in the wordlist cache so the
// offline fallback has a stable path and needs no cleanup.
func writeBundledList(toolsDir, name string, entries []string) (string, error) {
	if toolsDir == "" {
		return "", fmt.Errorf("no tools directory available for the bundled wordlist")
	}
	dir := filepath.Join(toolsDir, wordlistCacheDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "bundled-"+name+".txt")
	if err := os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// countWordlistEntries counts the non-empty lines of a wordlist.
func countWordlistEntries(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	count := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	return count, sc.Err()
}

// defaultWordlistProfile returns the profile a fuzzing mode uses when the
// caller does not pick one.
func defaultWordlistProfile(mode string) string {
	switch mode {
	case "vhost":
		return "hosts"
	case "param":
		return "params"
	default:
		return "dirs"
	}
}
