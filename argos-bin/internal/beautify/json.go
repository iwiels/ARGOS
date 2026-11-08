package beautify

import (
	"bytes"
	"encoding/json"
)

func FormatJSON(content string) (string, error) {
	var buf bytes.Buffer
	trimmed := []byte(content)
	err := json.Indent(&buf, trimmed, "", "  ")
	if err != nil {
		return content, err
	}
	return buf.String(), nil
}
