package beautify

import (
	"strings"
)

var voidTags = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

func FormatHTML(src string) (string, error) {
	var b strings.Builder
	indent := 0

	writeIndent := func(level int) {
		for i := 0; i < level; i++ {
			b.WriteString("  ")
		}
	}

	i := 0
	n := len(src)

	for i < n {
		// Skip whitespace between tags
		for i < n && (src[i] == ' ' || src[i] == '\t' || src[i] == '\r' || src[i] == '\n') {
			i++
		}
		if i >= n {
			break
		}

		// Comment: <!-- ... -->
		if strings.HasPrefix(src[i:], "<!--") {
			end := strings.Index(src[i:], "-->")
			if end == -1 {
				writeIndent(indent)
				b.WriteString(src[i:])
				b.WriteByte('\n')
				break
			}
			comment := src[i : i+end+3]
			writeIndent(indent)
			b.WriteString(comment)
			b.WriteByte('\n')
			i += end + 3
			continue
		}

		// DOCTYPE
		if strings.HasPrefix(strings.ToLower(src[i:]), "<!doctype") {
			end := strings.Index(src[i:], ">")
			if end == -1 {
				writeIndent(indent)
				b.WriteString(src[i:])
				b.WriteByte('\n')
				break
			}
			writeIndent(indent)
			b.WriteString(src[i : i+end+1])
			b.WriteByte('\n')
			i += end + 1
			continue
		}

		// Tag: <...>
		if src[i] == '<' {
			end := strings.Index(src[i:], ">")
			if end == -1 {
				writeIndent(indent)
				b.WriteString(src[i:])
				b.WriteByte('\n')
				break
			}

			tagContent := src[i+1 : i+end]
			isClosing := strings.HasPrefix(tagContent, "/")
			isSelfClosing := strings.HasSuffix(tagContent, "/")

			// Extract tag name
			fields := strings.Fields(tagContent)
			tagName := ""
			if len(fields) > 0 {
				tagName = strings.ToLower(strings.TrimPrefix(fields[0], "/"))
				tagName = strings.TrimSuffix(tagName, "/")
			}

			if isClosing {
				indent--
				if indent < 0 {
					indent = 0
				}
				writeIndent(indent)
				b.WriteString(src[i : i+end+1])
				b.WriteByte('\n')
				i += end + 1
				continue
			}

			// Script tag handling with nested JS beautification
			if tagName == "script" && !isSelfClosing {
				writeIndent(indent)
				b.WriteString(src[i : i+end+1])
				b.WriteByte('\n')
				i += end + 1

				closeIdx := strings.Index(strings.ToLower(src[i:]), "</script>")
				if closeIdx != -1 {
					scriptBody := src[i : i+closeIdx]
					trimmed := strings.TrimSpace(scriptBody)
					if len(trimmed) > 0 {
						formattedJS, err := FormatJS(trimmed)
						if err == nil {
							jsLines := strings.Split(formattedJS, "\n")
							for _, jl := range jsLines {
								if strings.TrimSpace(jl) != "" {
									writeIndent(indent + 1)
									b.WriteString(jl)
									b.WriteByte('\n')
								}
							}
						} else {
							writeIndent(indent + 1)
							b.WriteString(trimmed)
							b.WriteByte('\n')
						}
					}
					i += closeIdx
				}
				continue
			}

			// Style tag handling with nested CSS beautification
			if tagName == "style" && !isSelfClosing {
				writeIndent(indent)
				b.WriteString(src[i : i+end+1])
				b.WriteByte('\n')
				i += end + 1

				closeIdx := strings.Index(strings.ToLower(src[i:]), "</style>")
				if closeIdx != -1 {
					styleBody := src[i : i+closeIdx]
					trimmed := strings.TrimSpace(styleBody)
					if len(trimmed) > 0 {
						formattedCSS, err := FormatCSS(trimmed)
						if err == nil {
							cssLines := strings.Split(formattedCSS, "\n")
							for _, cl := range cssLines {
								if strings.TrimSpace(cl) != "" {
									writeIndent(indent + 1)
									b.WriteString(cl)
									b.WriteByte('\n')
								}
							}
						} else {
							writeIndent(indent + 1)
							b.WriteString(trimmed)
							b.WriteByte('\n')
						}
					}
					i += closeIdx
				}
				continue
			}

			// Opening tag
			writeIndent(indent)
			b.WriteString(src[i : i+end+1])
			b.WriteByte('\n')
			i += end + 1

			if !isSelfClosing && !voidTags[tagName] {
				indent++
			}
			continue
		}

		// Text node
		nextTag := strings.Index(src[i:], "<")
		var text string
		if nextTag == -1 {
			text = src[i:]
			i = n
		} else {
			text = src[i : i+nextTag]
			i += nextTag
		}

		trimmedText := strings.TrimSpace(text)
		if len(trimmedText) > 0 {
			writeIndent(indent)
			b.WriteString(trimmedText)
			b.WriteByte('\n')
		}
	}

	return cleanExtraLines(b.String()), nil
}
