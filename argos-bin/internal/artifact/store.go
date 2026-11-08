package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/paths"
)

type ArtifactMeta struct {
	ID             string          `json:"id"`
	Target         string          `json:"target"`
	Host           string          `json:"host"`
	Type           string          `json:"type"`
	OriginalSize   int             `json:"original_size"`
	BeautifiedSize int             `json:"beautified_size"`
	TotalLines     int             `json:"total_lines"`
	Endpoints      []string        `json:"endpoints"`
	Secrets        []SecretFinding `json:"secrets"`
	SourceMap      string          `json:"sourcemap,omitempty"`
	CreatedAt      string          `json:"created_at"`
	FilePath       string          `json:"file_path"`
}

type LineEntry struct {
	Number  int    `json:"line"`
	Content string `json:"content"`
}

type SearchResult struct {
	MatchLine   int         `json:"match_line"`
	MatchedText string      `json:"matched_text"`
	Context     []LineEntry `json:"context"`
}

type ArtifactStore struct {
	BaseDir string
}

func NewStore(memoryDir string) *ArtifactStore {
	if memoryDir == "" {
		home, _ := os.UserHomeDir()
		memoryDir = paths.ResolveMemoryDir(home)
	}
	base := filepath.Join(memoryDir, "artifacts")
	os.MkdirAll(base, 0o755)
	return &ArtifactStore{BaseDir: base}
}

func GenerateArtifactID(target string) string {
	h := sha256.Sum256([]byte(target))
	return "art_" + hex.EncodeToString(h[:4])
}

func CleanHost(target string) string {
	u, err := url.Parse(target)
	if err == nil && u.Host != "" {
		h := u.Hostname()
		return strings.ReplaceAll(h, ":", "_")
	}
	cleaned := strings.ReplaceAll(target, "://", "_")
	cleaned = strings.ReplaceAll(cleaned, "/", "_")
	cleaned = strings.ReplaceAll(cleaned, "\\", "_")
	cleaned = strings.ReplaceAll(cleaned, ":", "_")
	if len(cleaned) > 40 {
		cleaned = cleaned[:40]
	}
	return cleaned
}

func (s *ArtifactStore) Save(meta *ArtifactMeta, content string) error {
	hostDir := filepath.Join(s.BaseDir, CleanHost(meta.Host))
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		return err
	}

	ext := "txt"
	switch meta.Type {
	case "javascript":
		ext = "js"
	case "html":
		ext = "html"
	case "css":
		ext = "css"
	case "json":
		ext = "json"
	}

	contentPath := filepath.Join(hostDir, fmt.Sprintf("%s.%s", meta.ID, ext))
	metaPath := filepath.Join(hostDir, fmt.Sprintf("%s.json", meta.ID))

	if err := os.WriteFile(contentPath, []byte(content), 0o644); err != nil {
		return err
	}

	meta.FilePath = contentPath
	meta.BeautifiedSize = len(content)
	meta.TotalLines = len(strings.Split(content, "\n"))
	meta.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, metaBytes, 0o644)
}

func (s *ArtifactStore) FindMetaAndContent(idOrTarget string) (*ArtifactMeta, string, error) {
	// Search in all host subdirectories
	entries, err := os.ReadDir(s.BaseDir)
	if err != nil {
		return nil, "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		hostDir := filepath.Join(s.BaseDir, entry.Name())
		files, _ := os.ReadDir(hostDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".json") {
				metaBytes, err := os.ReadFile(filepath.Join(hostDir, f.Name()))
				if err != nil {
					continue
				}
				var meta ArtifactMeta
				if json.Unmarshal(metaBytes, &meta) == nil {
					if meta.ID == idOrTarget || meta.Target == idOrTarget || meta.FilePath == idOrTarget {
						contentBytes, err := os.ReadFile(meta.FilePath)
						if err == nil {
							return &meta, string(contentBytes), nil
						}
					}
				}
			}
		}
	}
	return nil, "", fmt.Errorf("artifact %q not found", idOrTarget)
}

func (s *ArtifactStore) ReadLines(idOrTarget string, startLine, limit int) ([]LineEntry, bool, int, error) {
	_, content, err := s.FindMetaAndContent(idOrTarget)
	if err != nil {
		return nil, false, 0, err
	}

	lines := strings.Split(content, "\n")
	total := len(lines)

	if startLine <= 0 {
		startLine = 1
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	startIdx := startLine - 1
	if startIdx >= total {
		return []LineEntry{}, false, total, nil
	}

	endIdx := startIdx + limit
	if endIdx > total {
		endIdx = total
	}

	var result []LineEntry
	for i := startIdx; i < endIdx; i++ {
		result = append(result, LineEntry{
			Number:  i + 1,
			Content: lines[i],
		})
	}

	hasMore := endIdx < total
	return result, hasMore, total, nil
}

func (s *ArtifactStore) Search(idOrTarget string, pattern string, contextLines int) ([]SearchResult, error) {
	_, content, err := s.FindMetaAndContent(idOrTarget)
	if err != nil {
		return nil, err
	}

	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	if contextLines <= 0 {
		contextLines = 2
	}
	if contextLines > 5 {
		contextLines = 5
	}

	lines := strings.Split(content, "\n")
	total := len(lines)
	var results []SearchResult

	for idx, line := range lines {
		if re.MatchString(line) {
			start := max(0, idx-contextLines)
			end := min(total, idx+contextLines+1)

			var ctxEntries []LineEntry
			for c := start; c < end; c++ {
				ctxEntries = append(ctxEntries, LineEntry{
					Number:  c + 1,
					Content: lines[c],
				})
			}

			results = append(results, SearchResult{
				MatchLine:   idx + 1,
				MatchedText: strings.TrimSpace(line),
				Context:     ctxEntries,
			})

			if len(results) >= 50 {
				break
			}
		}
	}

	return results, nil
}
