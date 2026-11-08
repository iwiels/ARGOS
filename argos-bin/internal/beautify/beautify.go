package beautify

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

type Language string

const (
	LangJS      Language = "javascript"
	LangHTML    Language = "html"
	LangCSS     Language = "css"
	LangJSON    Language = "json"
	LangUnknown Language = "unknown"
)

func DetectLanguage(nameOrURL, content string) Language {
	clean := strings.ToLower(nameOrURL)
	if idx := strings.Index(clean, "?"); idx != -1 {
		clean = clean[:idx]
	}
	if idx := strings.Index(clean, "#"); idx != -1 {
		clean = clean[:idx]
	}

	ext := filepath.Ext(clean)
	switch ext {
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx":
		return LangJS
	case ".html", ".htm", ".xhtml":
		return LangHTML
	case ".css", ".scss", ".less":
		return LangCSS
	case ".json":
		return LangJSON
	}

	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "<!DOCTYPE") || strings.HasPrefix(trimmed, "<html") || strings.HasPrefix(trimmed, "<head") || strings.HasPrefix(trimmed, "<div") {
		return LangHTML
	}
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) || (strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		var js json.RawMessage
		if json.Unmarshal([]byte(trimmed), &js) == nil {
			return LangJSON
		}
	}
	if strings.Contains(trimmed, "function") || strings.Contains(trimmed, "var ") || strings.Contains(trimmed, "const ") || strings.Contains(trimmed, "let ") || strings.Contains(trimmed, "=>") {
		return LangJS
	}
	if strings.Contains(trimmed, "{") && strings.Contains(trimmed, ":") && strings.Contains(trimmed, ";") && !strings.Contains(trimmed, "function") {
		return LangCSS
	}

	return LangJS
}

func Beautify(content string, lang Language) (string, error) {
	switch lang {
	case LangJSON:
		return FormatJSON(content)
	case LangHTML:
		return FormatHTML(content)
	case LangCSS:
		return FormatCSS(content)
	case LangJS:
		return FormatJS(content)
	default:
		return FormatJS(content)
	}
}
