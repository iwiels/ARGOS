package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DetectRuntime returns the executable path for the requested runtime (python, bash, ruby).
func DetectRuntime(rt string) (string, error) {
	switch strings.ToLower(rt) {
	case "python", "python3":
		for _, name := range []string{"python3", "python", "py"} {
			if path, err := exec.LookPath(name); err == nil {
				return path, nil
			}
		}
		return "", fmt.Errorf("Python 3 runtime no encontrado en PATH")
	case "bash":
		if path, err := exec.LookPath("bash"); err == nil {
			return path, nil
		}
		if runtime.GOOS == "windows" {
			gitBash := `C:\Program Files\Git\bin\bash.exe`
			if _, err := os.Stat(gitBash); err == nil {
				return gitBash, nil
			}
			gitBash86 := `C:\Program Files (x86)\Git\bin\bash.exe`
			if _, err := os.Stat(gitBash86); err == nil {
				return gitBash86, nil
			}
			if wsl, err := exec.LookPath("wsl.exe"); err == nil {
				return wsl, nil
			}
		}
		return "", fmt.Errorf("Bash runtime no encontrado (instala Git for Windows o WSL)")
	case "ruby":
		if path, err := exec.LookPath("ruby"); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("Ruby runtime no encontrado en PATH")
	default:
		return "", fmt.Errorf("runtime no soportado: %s", rt)
	}
}

// EnsureVenv creates and initializes a Python virtualenv for pip packages under baseDir/toolName/venv.
func EnsureVenv(ctx context.Context, baseDir, toolName, pkg string) (string, error) {
	venvDir := filepath.Join(baseDir, toolName, "venv")
	marker := filepath.Join(venvDir, ".installed")
	var binPath string
	if runtime.GOOS == "windows" {
		binPath = filepath.Join(venvDir, "Scripts", toolName+".exe")
	} else {
		binPath = filepath.Join(venvDir, "bin", toolName)
	}

	if _, err := os.Stat(marker); err == nil {
		if _, err := os.Stat(binPath); err == nil {
			return binPath, nil
		}
	}

	py, err := DetectRuntime("python")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(venvDir), 0o755); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, py, "-m", "venv", venvDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("fallo al crear venv: %s (%w)", string(out), err)
	}

	var pipBin string
	if runtime.GOOS == "windows" {
		pipBin = filepath.Join(venvDir, "Scripts", "pip.exe")
	} else {
		pipBin = filepath.Join(venvDir, "bin", "pip")
	}

	cmdInstall := exec.CommandContext(ctx, pipBin, "install", "--upgrade", pkg)
	if out, err := cmdInstall.CombinedOutput(); err != nil {
		return "", fmt.Errorf("pip install %s fallo: %s (%w)", pkg, string(out), err)
	}
	_ = os.WriteFile(marker, []byte(pkg), 0o644)
	return binPath, nil
}
