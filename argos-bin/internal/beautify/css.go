package beautify

import (
	"strings"
)

func FormatCSS(src string) (string, error) {
	var b strings.Builder
	indent := 0
	inComment := false
	inString := false
	var stringChar rune

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

		// Multi-line comment
		if inComment {
			b.WriteRune(r)
			if r == '*' && i+1 < n && runes[i+1] == '/' {
				b.WriteRune('/')
				i++
				inComment = false
				b.WriteByte('\n')
				writeIndent()
				isLineStart = true
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

		// Comment start
		if r == '/' && i+1 < n && runes[i+1] == '*' {
			inComment = true
			if !isLineStart {
				b.WriteByte('\n')
				writeIndent()
			}
			b.WriteString("/*")
			i++
			isLineStart = false
			continue
		}

		// String start
		if r == '"' || r == '\'' {
			inString = true
			stringChar = r
			b.WriteRune(r)
			isLineStart = false
			continue
		}

		// Braces
		if r == '{' {
			if !isLineStart && b.Len() > 0 && b.String()[b.Len()-1] != ' ' {
				b.WriteByte(' ')
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
			lastStr := b.String()
			if len(lastStr) > 0 && lastStr[len(lastStr)-1] != '\n' {
				b.WriteByte('\n')
			}
			writeIndent()
			b.WriteString("}\n\n")
			writeIndent()
			isLineStart = true
			continue
		}

		// Semicolons
		if r == ';' {
			b.WriteString(";\n")
			writeIndent()
			isLineStart = true
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

		// Commas
		if r == ',' {
			b.WriteString(", ")
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
