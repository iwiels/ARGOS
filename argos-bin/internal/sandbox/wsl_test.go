package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsToWslPath(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{`C:\Users\test\argos-auditor`, `/mnt/c/Users/test/argos-auditor`},
		{`D:\scans\report.json`, `/mnt/d/scans/report.json`},
		{`c:/Users/test/test`, `/mnt/c/Users/test/test`},
		{`/usr/bin/nmap`, `/usr/bin/nmap`},
		{`relative/path/file.txt`, `relative/path/file.txt`},
		{`--output-file`, `--output-file`},
	}

	for _, c := range cases {
		got := WindowsToWslPath(c.input)
		if got != c.expected {
			t.Errorf("WindowsToWslPath(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		b[2*i] = byte(v)
		b[2*i+1] = byte(v >> 8)
	}
	return b
}

func decodeWslOutput(b []byte) string {
	if len(b) >= 2 && (b[0] == 0xff && b[1] == 0xfe) {
		return decodeUTF16LE(b[2:])
	}
	zeroCount := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			zeroCount++
		}
	}
	if len(b) > 2 && zeroCount >= len(b)/4 {
		return decodeUTF16LE(b)
	}
	return string(b)
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(b[2*i]) | (uint16(b[2*i+1]) << 8)
	}
	return string(utf16.Decode(u16))
}

func parseWslDistros(output string) []string {
	var distros []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		clean := strings.TrimSpace(strings.ReplaceAll(line, "\x00", ""))
		clean = strings.TrimPrefix(clean, "*")
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		lower := strings.ToLower(clean)
		if strings.HasPrefix(lower, "docker-desktop") {
			continue
		}
		distros = append(distros, clean)
	}
	return distros
}

func selectPreferredDistro(distros []string) string {
	if override := os.Getenv("ARGOS_WSL_DISTRO"); override != "" {
		for _, d := range distros {
			if strings.EqualFold(d, override) {
				return d
			}
		}
		return override
	}

	for _, d := range distros {
		lower := strings.ToLower(d)
		if strings.Contains(lower, "kali") {
			return d
		}
	}

	for _, d := range distros {
		lower := strings.ToLower(d)
		if strings.Contains(lower, "ubuntu") {
			return d
		}
	}

	for _, d := range distros {
		lower := strings.ToLower(d)
		if strings.Contains(lower, "debian") {
			return d
		}
	}

	if len(distros) > 0 {
		return distros[0]
	}
	return ""
}

func TestDecodeWslOutput(t *testing.T) {
	raw := "kali-linux\r\ndocker-desktop\r\nUbuntu-22.04\r\n"
	encoded := encodeUTF16LE(raw)

	decoded := decodeWslOutput(encoded)
	if decoded != raw {
		t.Fatalf("decodeWslOutput failed: got %q, want %q", decoded, raw)
	}

	// Also test standard UTF-8 string without encoding
	utf8Decoded := decodeWslOutput([]byte(raw))
	if utf8Decoded != raw {
		t.Fatalf("decodeWslOutput UTF-8 failed: got %q, want %q", utf8Decoded, raw)
	}
}

func TestParseAndSelectPreferredDistro(t *testing.T) {
	output := "* kali-linux\r\n  docker-desktop\r\n  docker-desktop-data\r\n  Ubuntu-22.04\r\n"
	distros := parseWslDistros(output)

	if len(distros) != 2 {
		t.Fatalf("expected 2 valid distros (kali and ubuntu), got %d: %v", len(distros), distros)
	}
	if distros[0] != "kali-linux" || distros[1] != "Ubuntu-22.04" {
		t.Fatalf("unexpected distros list: %v", distros)
	}

	// Check preference: kali must be chosen first
	pref := selectPreferredDistro(distros)
	if pref != "kali-linux" {
		t.Fatalf("expected 'kali-linux' to be preferred, got %q", pref)
	}

	// Check env override
	os.Setenv("ARGOS_WSL_DISTRO", "Ubuntu-22.04")
	defer os.Unsetenv("ARGOS_WSL_DISTRO")

	overridden := selectPreferredDistro(distros)
	if overridden != "Ubuntu-22.04" {
		t.Fatalf("expected 'Ubuntu-22.04' due to ARGOS_WSL_DISTRO override, got %q", overridden)
	}
}

func TestWslExecutorIsRuntimeNotSandbox(t *testing.T) {
	w := &WslExecutor{available: true, distro: "Ubuntu"}
	if w.IsSandboxed() {
		t.Fatal("WSL runtime must not claim command-level sandboxing")
	}
	if !strings.HasPrefix(w.Name(), "wsl2-runtime:") {
		t.Fatalf("expected runtime name to identify WSL without claiming isolation, got %q", w.Name())
	}
}

func TestWslExecutorDoesNotRunAuditCommandsOutsideDocker(t *testing.T) {
	w := &WslExecutor{available: true, distro: "Ubuntu"}
	result, err := w.Execute(context.Background(), CommandSpec{Path: "echo", Args: []string{"must-not-run"}})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "docker") {
		t.Fatalf("expected an explicit Docker isolation requirement, got result=%+v error=%v", result, err)
	}
	if result != nil {
		t.Fatalf("WSL executor returned an unsandboxed command result: %+v", result)
	}
}

func TestWslExecutorDoesNotFallBackToTheHost(t *testing.T) {
	tests := []struct {
		name      string
		executor  *WslExecutor
		clearPath bool
	}{
		{name: "WSL unavailable", executor: &WslExecutor{}},
		{name: "WSL command cannot start", executor: &WslExecutor{available: true, distro: "test-distro"}, clearPath: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.clearPath {
				t.Setenv("PATH", t.TempDir())
			}
			result, err := tt.executor.Execute(context.Background(), CommandSpec{Path: "echo", Args: []string{"host-fallback-must-not-run"}})
			if err == nil {
				t.Fatal("expected WSL execution to fail closed instead of falling back to the host")
			}
			if result != nil {
				t.Fatalf("blocked WSL execution returned a host result: %+v", result)
			}
			if tt.executor.Name() == "host" {
				t.Fatal("an unavailable WSL executor must not report the host as its runtime")
			}
		})
	}
}
