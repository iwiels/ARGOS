package tools

import (
	"encoding/json"
	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
	"log"
	"os"
	"path/filepath"
)

// toolConfigOverride is the shape of a webTools entry in argos.jsonc.
// Empty fields inherit from the compiled-in default spec.
type toolConfigOverride struct {
	Repo    string `json:"repo"`
	Version string `json:"version"`
	Bin     string `json:"bin"`
	Archive string `json:"archive"`
	// TemplatesVersion pins the community template set used by nuclei.
	TemplatesVersion string `json:"templatesVersion"`
	// RateLimit is the nuclei requests-per-second ceiling.
	RateLimit int `json:"rateLimit"`
	// Concurrency is the number of templates nuclei runs in parallel.
	Concurrency int `json:"concurrency"`
	// Packs narrows the Argos template packs of a scan, in order. Empty runs
	// every pack enabled in the packs registry.
	Packs []string `json:"packs"`
}

// stripJSONC removes // and /* */ comments while preserving string contents.
func stripJSONC(src []byte) []byte {
	out := make([]byte, 0, len(src))
	inStr := false
	esc := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inStr {
			out = append(out, c)
			if esc {
				esc = false
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i++ // consume the closing '/'
		default:
			out = append(out, c)
		}
	}
	return out
}

// configFiles son los nombres aceptados del archivo de config dentro de
// $OPENCODE_CONFIG_DIR.
var configFiles = []string{"argos.jsonc"}

// loadWebToolsOverrides collects the webTools overrides from the config file
// and the environment variable, in increasing order of precedence.
func loadWebToolsOverrides() map[string]toolConfigOverride {
	overrides := map[string]toolConfigOverride{}

	// lowest precedence: argos.jsonc webTools block (when OPENCODE_CONFIG_DIR is set)
	if dir := os.Getenv("OPENCODE_CONFIG_DIR"); dir != "" {
		for _, configFile := range configFiles {
			path := filepath.Join(dir, configFile)
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var doc struct {
				WebTools map[string]toolConfigOverride `json:"webTools"`
			}
			if err := json.Unmarshal(stripJSONC(raw), &doc); err == nil {
				mergeOverrides(overrides, doc.WebTools)
			} else {
				log.Printf("argos-web: ignoring malformed webTools in %s: %v", path, err)
			}
		}
	}

	// highest precedence: ARGOS_WEB_TOOLS_CONFIG (JSON string, e.g. injected by the sidecar)
	if envConfig := env.Get("ARGOS_WEB_TOOLS_CONFIG"); envConfig != "" {
		var m map[string]toolConfigOverride
		if err := json.Unmarshal([]byte(envConfig), &m); err == nil {
			mergeOverrides(overrides, m)
		} else {
			log.Printf("argos-web: ignoring malformed ARGOS_WEB_TOOLS_CONFIG: %v", err)
		}
	}
	return overrides
}

// loadWebToolsConfig returns the effective tool specs: compiled-in defaults
// merged with overrides from $OPENCODE_CONFIG_DIR/argos.jsonc (webTools) and
// $ARGOS_WEB_TOOLS_CONFIG (JSON string, highest precedence).
func loadWebToolsConfig() []BinarySpec {
	overrides := loadWebToolsOverrides()

	specs := make([]BinarySpec, len(binSpecs))
	copy(specs, binSpecs)
	for i := range specs {
		o, ok := overrides[specs[i].Name]
		if !ok {
			continue
		}
		if o.Repo != "" {
			specs[i].Repo = o.Repo
		}
		if o.Version != "" {
			specs[i].Version = o.Version
		}
		if o.Bin != "" {
			specs[i].Bin = o.Bin
		}
		if o.Archive != "" {
			specs[i].Archive = o.Archive
		}
		if specs[i].Name == "naabu" && (specs[i].Repo != "projectdiscovery/naabu" || specs[i].Version != "v2.3.1") {
			specs[i].UnsupportedTargets = nil
		}
	}

	// webTools.nuclei.templatesVersion pins the community template set; it
	// wins over the generic webTools["nuclei-templates"].version entry.
	if o, ok := overrides["nuclei"]; ok && o.TemplatesVersion != "" {
		for i := range specs {
			if specs[i].Name == "nuclei-templates" {
				specs[i].Version = o.TemplatesVersion
			}
		}
	}

	// the checksum pin must always match the effective version
	for i := range specs {
		if specs[i].Kind == "templates" {
			specs[i].SHA256 = nucleiTemplatesSHA256[specs[i].Version]
		}
	}
	return specs
}

// nucleiScanConfig holds the web.scan knobs that can be pinned from argos.jsonc.
// The template set version is not part of it: webTools.nuclei.templatesVersion
// is applied to the nuclei-templates spec (see loadWebToolsConfig).
type nucleiScanConfig struct {
	RateLimit   int
	Concurrency int
	Packs       []string
}

const (
	defaultNucleiRateLimit   = 10
	defaultNucleiConcurrency = 25
)

// loadNucleiScanConfig returns the effective web.scan configuration: the
// webTools.nuclei block of argos.jsonc merged over the compiled-in defaults.
func loadNucleiScanConfig() nucleiScanConfig {
	o := loadWebToolsOverrides()["nuclei"]
	cfg := nucleiScanConfig{
		RateLimit:   o.RateLimit,
		Concurrency: o.Concurrency,
		Packs:       o.Packs,
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = defaultNucleiRateLimit
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultNucleiConcurrency
	}
	return cfg
}

func mergeOverrides(dst, src map[string]toolConfigOverride) {
	for k, v := range src {
		dst[k] = v
	}
}
