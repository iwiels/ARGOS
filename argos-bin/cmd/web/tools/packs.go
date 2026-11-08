package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	argosenv "github.com/iwiels/argos-auditor/argos-bin/internal/env"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

// PacksDirEnv overrides the directory that holds the Argos nuclei template
// packs. It exists for development and for installs that ship the packs
// outside the config directory.
const PacksDirEnv = "ARGOS_NUCLEI_PACKS_DIR"

// Pack is one entry of argos-config/templates/nuclei/registry.json.
//
// The registry is data: a pack can be disabled without deleting its templates,
// and an explicit request in web.scan can run a disabled pack for one scan.
type Pack struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Path         string   `json:"path"`
	Enabled      bool     `json:"enabled"`
	RequiresAuth bool     `json:"requiresAuth"`
	MinSeverity  string   `json:"minSeverity"`
	Tags         []string `json:"tags"`
	Notes        string   `json:"notes"`
}

// PackRegistry is the catalog of Argos template packs.
type PackRegistry struct {
	Version int    `json:"version"`
	Packs   []Pack `json:"packs"`
}

// TemplateSummary is the catalog entry of one template file. It is read from
// the file itself so the catalog cannot drift from the templates.
type TemplateSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	File     string `json:"file"`
}

// ResolvePacksDir returns the directory of the Argos template packs, or "".
//
// Order: the explicit override, the config directory the desktop sets, and
// finally the argos-config that sits next to the binary in a source checkout.
func ResolvePacksDir() string {
	if dir := strings.TrimSpace(argosenv.Get(PacksDirEnv)); dir != "" {
		return dir
	}
	if dir := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG_DIR")); dir != "" {
		if candidate := filepath.Join(dir, "templates", "nuclei"); isDir(candidate) {
			return candidate
		}
	}
	if exe, err := os.Executable(); err == nil {
		if candidate := filepath.Join(filepath.Dir(exe), "..", "argos-config", "templates", "nuclei"); isDir(candidate) {
			return candidate
		}
	}
	return ""
}

// LoadPacks reads and validates the pack registry.
//
// A registry that points outside its own directory is rejected: the file is
// operator-editable config, and a pack path is a directory handed to nuclei.
func LoadPacks(dir string) (PackRegistry, error) {
	var registry PackRegistry
	if strings.TrimSpace(dir) == "" {
		return registry, fmt.Errorf("nuclei template packs directory is not configured")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "registry.json"))
	if err != nil {
		return registry, fmt.Errorf("reading nuclei template pack registry: %w", err)
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		return registry, fmt.Errorf("parsing nuclei template pack registry: %w", err)
	}

	seen := map[string]bool{}
	for i := range registry.Packs {
		pack := &registry.Packs[i]
		pack.ID = strings.ToLower(strings.TrimSpace(pack.ID))
		if pack.ID == "" {
			return registry, fmt.Errorf("nuclei template pack registry: entry %d has no id", i)
		}
		if seen[pack.ID] {
			return registry, fmt.Errorf("nuclei template pack registry: duplicate pack id %q", pack.ID)
		}
		seen[pack.ID] = true
		pack.Path = strings.TrimSpace(pack.Path)
		if pack.Path == "" {
			pack.Path = pack.ID
		}
		if !filepath.IsLocal(pack.Path) {
			return registry, fmt.Errorf("nuclei template pack registry: pack %q escapes the packs directory", pack.ID)
		}
	}
	return registry, nil
}

// SelectPacks resolves the packs of a scan. An empty request means every
// enabled pack; an explicit request wins over the enabled flag so an operator
// can run a disabled pack without editing the registry.
func SelectPacks(registry PackRegistry, requested []string) ([]Pack, error) {
	wanted := map[string]bool{}
	for _, raw := range requested {
		if id := strings.ToLower(strings.TrimSpace(raw)); id != "" {
			wanted[id] = true
		}
	}

	if len(wanted) == 0 {
		out := make([]Pack, 0, len(registry.Packs))
		for _, pack := range registry.Packs {
			if pack.Enabled {
				out = append(out, pack)
			}
		}
		return out, nil
	}

	byID := make(map[string]Pack, len(registry.Packs))
	for _, pack := range registry.Packs {
		byID[pack.ID] = pack
	}

	out := make([]Pack, 0, len(wanted))
	unknown := make([]string, 0)
	for _, raw := range requested {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" || !wanted[id] {
			continue
		}
		wanted[id] = false
		pack, ok := byID[id]
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		out = append(out, pack)
	}
	if len(unknown) > 0 {
		known := make([]string, 0, len(byID))
		for id := range byID {
			known = append(known, id)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("unknown nuclei template pack(s) %s; known packs: %s",
			strings.Join(unknown, ", "), strings.Join(known, ", "))
	}
	return out, nil
}

// PackDirs resolves the directories of the selected packs. A pack whose
// directory is missing is reported, not silently skipped: the scan result has
// to say that coverage was lower than requested.
func PackDirs(baseDir string, packs []Pack) (dirs []string, missing []string) {
	for _, pack := range packs {
		dir := filepath.Join(baseDir, pack.Path)
		if isDir(dir) {
			dirs = append(dirs, dir)
			continue
		}
		missing = append(missing, pack.ID)
	}
	return dirs, missing
}

// PacksFingerprint is the content hash of the template files that ran. Paths
// are relative to the packs directory, so the same packs produce the same hash
// on every machine.
func PacksFingerprint(baseDir string, dirs []string) string {
	files := make([]string, 0)
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}
	sort.Strings(files)

	hash := sha256.New()
	for _, path := range files {
		relative, err := filepath.Rel(baseDir, path)
		if err != nil {
			relative = filepath.Base(path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		fmt.Fprintf(hash, "%s\x00%x\n", filepath.ToSlash(relative), sum)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// PackTemplates reads the catalog entries of a pack directory.
func PackTemplates(dir string) []TemplateSummary {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []TemplateSummary{}
	}
	out := make([]TemplateSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		if summary, ok := readTemplateSummary(filepath.Join(dir, entry.Name())); ok {
			summary.File = entry.Name()
			out = append(out, summary)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// readTemplateSummary extracts the id, name and severity of a template. It is
// a line scan on purpose: the catalog must not need a YAML parser, and the
// three keys are fixed by the template contract.
func readTemplateSummary(path string) (TemplateSummary, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return TemplateSummary{}, false
	}
	var summary TemplateSummary
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case summary.ID == "" && strings.HasPrefix(line, "id:"):
			summary.ID = unquote(strings.TrimSpace(strings.TrimPrefix(line, "id:")))
		case summary.Name == "" && strings.HasPrefix(line, "  name:"):
			summary.Name = unquote(strings.TrimSpace(strings.TrimPrefix(line, "  name:")))
		case summary.Severity == "" && strings.HasPrefix(line, "  severity:"):
			summary.Severity = unquote(strings.TrimSpace(strings.TrimPrefix(line, "  severity:")))
		}
	}
	return summary, summary.ID != ""
}

func unquote(value string) string {
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// RegisterTemplatePacks registers web.templates: the catalog the agent reads
// before choosing packs for a scan. It is read-only and never touches a target.
func RegisterTemplatePacks(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.templates",
			Description: "List the Argos nuclei template packs bundled with the install: id, purpose, whether the pack needs an authenticated session, the severity floor it guarantees and the templates it contains. " +
				"Read-only. Use it before web.scan to pick packs by name (web.scan accepts `packs`) or to know which classes are covered by Argos itself instead of the community set.",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]mcp.Property{},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			dir := ResolvePacksDir()
			res := map[string]interface{}{
				"tool":      "web.templates",
				"packs_dir": dir,
				"available": false,
				"packs":     []map[string]any{},
			}

			registry, err := LoadPacks(dir)
			if err != nil {
				res["warning"] = err.Error()
				res["summary"] = "no template packs available"
				return res, nil
			}

			packs := make([]map[string]any, 0, len(registry.Packs))
			total := 0
			for _, pack := range registry.Packs {
				dirs, missing := PackDirs(dir, []Pack{pack})
				templates := []TemplateSummary{}
				if len(dirs) == 1 {
					templates = PackTemplates(dirs[0])
				}
				total += len(templates)
				entry := map[string]any{
					"id":             pack.ID,
					"name":           pack.Name,
					"description":    pack.Description,
					"enabled":        pack.Enabled,
					"requires_auth":  pack.RequiresAuth,
					"min_severity":   pack.MinSeverity,
					"tags":           pack.Tags,
					"notes":          pack.Notes,
					"templates":      templates,
					"template_count": len(templates),
				}
				if len(missing) > 0 {
					entry["missing"] = true
				}
				packs = append(packs, entry)
			}

			res["available"] = true
			res["registry_version"] = registry.Version
			res["packs"] = packs
			res["total_templates"] = total
			res["summary"] = fmt.Sprintf("%d packs, %d templates", len(packs), total)
			return res, nil
		},
	)
}
