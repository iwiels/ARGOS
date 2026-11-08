package tools

import "runtime"

// BinarySpec describes a third-party MIT/Apache/BSD binary the server fetches
// on demand from GitHub releases. Versions are pinned for reproducibility.
type BinarySpec struct {
	Name    string // tool key, e.g. "nuclei"
	Repo    string // "owner/repo"
	Version string // GitHub tag, e.g. "v3.11.0"
	Bin     string // executable name inside the archive
	Archive string // "zip" or "tar.gz"
	Kind    string // "" / "binary", "source", "bundle", "pip", "templates"
	Runtime string // "" / "binary", "python", "bash", "ruby"
	Pkg     string // PyPI package name if Kind == "pip"
	SHA256  string // expected sha256 of the downloaded archive (optional pin)
	// AssetTemplate names the release asset when the vendor does not follow
	// the <tool>_<os>_<arch> convention. The "{platform}" placeholder
	// expands to the token of the current platform (see AssetPlatforms).
	AssetTemplate string
	// AssetPlatforms maps the GOOS of the build onto the vendor's platform
	// token. It is only read when AssetTemplate is set.
	AssetPlatforms map[string]string
	// AssetArch is the GOARCH the vendor publishes builds for. Empty means
	// the archive is not architecture specific.
	AssetArch          string
	UnsupportedTargets []string
	// MaxDownloadBytes raises the archive size cap for the tools whose
	// bundle does not fit in the default one (the CodeQL CLI ships a
	// ~400MB-1.1GB bundle depending on the platform).
	MaxDownloadBytes int64
	// RequireChecksum makes an unverifiable download a hard error. It is set
	// for the vendors that publish a digest per asset: an unparseable
	// checksum file then means the release changed shape, not that the
	// archive is trusted blindly.
	RequireChecksum bool
}

func (spec *BinarySpec) TargetExecutableNameFor(goos string) string {
	// template sets are data, not executables
	if spec.Kind == "templates" {
		return ""
	}
	if spec.Kind == "source" || spec.Kind == "pip" {
		return spec.Bin
	}
	if goos == "windows" {
		return spec.Bin + ".exe"
	}
	return spec.Bin
}

func (spec *BinarySpec) TargetExecutableName() string {
	targetOS := runtime.GOOS
	if target, ok := defaultExecutor.(interface{ TargetOS() string }); ok {
		targetOS = target.TargetOS()
	}
	return spec.TargetExecutableNameFor(targetOS)
}

// downloadLimit is the maximum size of the archive the downloader accepts.
func (spec *BinarySpec) downloadLimit() int64 {
	if spec.MaxDownloadBytes > 0 {
		return spec.MaxDownloadBytes
	}
	return defaultDownloadLimit
}

var binSpecs = []BinarySpec{
	{Name: "nuclei", Repo: "projectdiscovery/nuclei", Version: "v3.11.0", Bin: "nuclei", Archive: "zip"},
	{Name: "nuclei-templates", Repo: "projectdiscovery/nuclei-templates", Version: "v10.4.0", Bin: "nuclei-templates", Archive: "zip", Kind: "templates"},
	{Name: "httpx", Repo: "projectdiscovery/httpx", Version: "v1.10.0", Bin: "httpx", Archive: "zip"},
	{Name: "katana", Repo: "projectdiscovery/katana", Version: "v1.6.1", Bin: "katana", Archive: "zip"},
	{Name: "subfinder", Repo: "projectdiscovery/subfinder", Version: "v2.14.0", Bin: "subfinder", Archive: "zip"},
	{Name: "dnsx", Repo: "projectdiscovery/dnsx", Version: "v1.3.0", Bin: "dnsx", Archive: "zip"},
	{Name: "interactsh-client", Repo: "projectdiscovery/interactsh", Version: "v1.3.1", Bin: "interactsh-client", Archive: "zip"},
	{Name: "gau", Repo: "lc/gau", Version: "v2.2.4", Bin: "gau", Archive: "zip"},
	{Name: "dalfox", Repo: "hahwul/dalfox", Version: "v3.2.0", Bin: "dalfox", Archive: "tar.gz"},
	{Name: "ffuf", Repo: "ffuf/ffuf", Version: "v2.2.1", Bin: "ffuf", Archive: "zip"},
	{Name: "sqlmap", Repo: "sqlmapproject/sqlmap", Version: "1.9", Bin: "sqlmap.py", Archive: "zip", Kind: "source", Runtime: "python"},
	{Name: "schemathesis", Repo: "schemathesis/schemathesis", Version: "v3.39.11", Bin: "schemathesis", Archive: "", Kind: "pip", Runtime: "python", Pkg: "schemathesis==3.39.11"},
	{Name: "tlsx", Repo: "projectdiscovery/tlsx", Version: "v1.1.7", Bin: "tlsx", Archive: "zip", Kind: "binary"},
	{Name: "naabu", Repo: "projectdiscovery/naabu", Version: "v2.3.1", Bin: "naabu", Archive: "zip", Kind: "binary", UnsupportedTargets: []string{"linux/arm64"}},
	{Name: "gitleaks", Repo: "gitleaks/gitleaks", Version: "v8.21.2", Bin: "gitleaks", Archive: "tar.gz", Kind: "binary"},
	{Name: "trivy", Repo: "aquasecurity/trivy", Version: "v0.58.2", Bin: "trivy", Archive: "tar.gz", Kind: "binary"},
	{Name: "semgrep", Repo: "semgrep/semgrep", Version: "v1.99.0", Bin: "semgrep", Archive: "", Kind: "pip", Runtime: "python", Pkg: "semgrep==1.99.0"},
	// CodeQL CLI: the release publishes one archive per platform
	// (codeql-win64.zip, codeql-linux64.zip, codeql-osx64.zip) plus a
	// sha256 digest per archive. The bundle is extracted as a tree because
	// the launcher needs its sibling directories (extractor packs, tools,
	// the bundled JRE) to work.
	{Name: "codeql", Repo: "github/codeql-cli-binaries", Version: "v2.20.7", Bin: "codeql", Archive: "zip", Kind: "bundle",
		AssetTemplate:    "codeql-{platform}.zip",
		AssetPlatforms:   map[string]string{"windows": "win64", "darwin": "osx64", "linux": "linux64"},
		AssetArch:        "amd64",
		MaxDownloadBytes: 2 << 30,
		RequireChecksum:  true},
}

// nucleiTemplatesSHA256 pins the sha256 of the nuclei-templates source archive
// per tag. The digests are the ones published by projectdiscovery in the
// nuclei-templates-<version>_checksums.txt release asset, which match the
// archive GitHub serves for the same tag.
var nucleiTemplatesSHA256 = map[string]string{
	"v10.4.0": "f880f8123adbe5a391431eaf6ac76f498898cb2d66b0a681c30094cf32b7c832",
}
