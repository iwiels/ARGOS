package beautify

import (
	"strings"
)

func FormatJS(src string) (string, error) {
	var b strings.Builder
	indent := 0
	inSingleLineComment := false
	inMultiLineComment := false
	inString := false
	var stringChar rune
	parenDepth := 0
	forHeaderParen := -1

	runes := []rune(src)
	n := len(runes)

	writeIndent := func() {
		for i := 0; i < indent; i++ {
			b.WriteString("  ")
		}
	}

	isLineStart := true

	for i := 0; i < n; i++ {
		r := runes[i]

		// Single line comment
		if inSingleLineComment {
			b.WriteRune(r)
			if r == '\n' {
				inSingleLineComment = false
				isLineStart = true
				writeIndent()
			}
			continue
		}

		// Multi-line comment
		if inMultiLineComment {
			b.WriteRune(r)
			if r == '*' && i+1 < n && runes[i+1] == '/' {
				b.WriteRune('/')
				i++
				inMultiLineComment = false
			}
			continue
		}

		// String literals
		if inString {
			b.WriteRune(r)
			if r == '\\' && i+1 < n {
				b.WriteRune(runes[i+1])
				i++
				continue
			}
			if r == stringChar {
				inString = false
			}
			continue
		}

		// Detect comments
		if r == '/' && i+1 < n {
			next := runes[i+1]
			if next == '/' {
				inSingleLineComment = true
				b.WriteString("//")
				i++
				continue
			}
			if next == '*' {
				inMultiLineComment = true
				b.WriteString("/*")
				i++
				continue
			}
		}

		// Detect string start
		if r == '"' || r == '\'' || r == '`' {
			inString = true
			stringChar = r
			b.WriteRune(r)
			isLineStart = false
			continue
		}

		// Track parentheses
		if r == '(' {
			parenDepth++
			b.WriteRune(r)
			// Check if previous token was 'for'
			if i >= 3 {
				sub := strings.TrimSpace(string(runes[max(0, i-6) : i]))
				if strings.HasSuffix(sub, "for") {
					forHeaderParen = parenDepth
				}
			}
			isLineStart = false
			continue
		}
		if r == ')' {
			if parenDepth == forHeaderParen {
				forHeaderParen = -1
			}
			parenDepth--
			if parenDepth < 0 {
				parenDepth = 0
			}
			b.WriteRune(r)
			isLineStart = false
			continue
		}

		// Braces
		if r == '{' {
			// If not empty object
			if i+1 < n && runes[i+1] == '}' {
				b.WriteString("{}")
				i++
				isLineStart = false
				continue
			}
			if !isLineStart && b.Len() > 0 {
				last := b.String()[b.Len()-1]
				if last != ' ' && last != '\n' && last != '(' {
					b.WriteByte(' ')
				}
			}
			b.WriteString("{\n")
			indent++
			writeIndent()
			isLineStart = true
			continue
		}
		if r == '}' {
			indent--
			if indent < 0 {
				indent = 0
			}
			// ensure on new line
			lastStr := b.String()
			if len(lastStr) > 0 && lastStr[len(lastStr)-1] != '\n' {
				b.WriteByte('\n')
			}
			writeIndent()
			b.WriteRune('}')
			// If followed by semicolon, else newline
			if i+1 < n && (runes[i+1] == ';' || runes[i+1] == ',' || runes[i+1] == ')') {
				isLineStart = false
			} else {
				b.WriteByte('\n')
				writeIndent()
				isLineStart = true
			}
			continue
		}

		// Semicolons
		if r == ';' {
			b.WriteRune(';')
			if forHeaderParen == -1 {
				b.WriteByte('\n')
				writeIndent()
				isLineStart = true
			} else {
				b.WriteByte(' ')
				isLineStart = false
			}
			continue
		}

		// Commas
		if r == ',' {
			b.WriteRune(',')
			b.WriteByte(' ')
			isLineStart = false
			continue
		}

		// Colons
		if r == ':' {
			b.WriteRune(':')
			if i+1 < n && runes[i+1] != ':' && runes[i+1] != ' ' {
				b.WriteByte(' ')
			}
			isLineStart = false
			continue
		}

		// Assignment / Equality Operators
		if r == '=' {
			if !isLineStart && b.Len() > 0 {
				last := b.String()[b.Len()-1]
				if last != ' ' && last != '!' && last != '<' && last != '>' && last != '+' && last != '-' && last != '*' && last != '/' && last != '=' {
					b.WriteByte(' ')
				}
			}
			b.WriteRune('=')
			if i+1 < n && runes[i+1] == '=' {
				b.WriteRune('=')
				i++
				if i+1 < n && runes[i+1] == '=' {
					b.WriteRune('=')
					i++
				}
			} else if i+1 < n && runes[i+1] == '>' {
				b.WriteRune('>')
				i++
			}
			if i+1 < n && runes[i+1] != ' ' && runes[i+1] != '\n' {
				b.WriteByte(' ')
			}
			isLineStart = false
			continue
		}

		// Whitespace
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			if isLineStart {
				continue
			}
			lastStr := b.String()
			if len(lastStr) > 0 && lastStr[len(lastStr)-1] != ' ' && lastStr[len(lastStr)-1] != '\n' {
				b.WriteByte(' ')
			}
			continue
		}

		b.WriteRune(r)
		isLineStart = false
	}

	return cleanExtraLines(b.String()), nil
}

func cleanExtraLines(s string) string {
	lines := strings.Split(s, "\n")
	var result []string
	consecutiveBlank := 0
	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(trimmed) == "" {
			consecutiveBlank++
			if consecutiveBlank <= 1 {
				result = append(result, "")
			}
		} else {
			consecutiveBlank = 0
			result = append(result, trimmed)
		}
	}
	return strings.TrimSpace(strings.Join(result, "\n")) + "\n"
}
