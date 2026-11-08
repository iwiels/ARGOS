package sandbox

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

type WslExecutor struct {
	distro    string
	available bool
}

func (w *WslExecutor) IsAvailable() bool {
	return w.available
}

func (w *WslExecutor) IsSandboxed() bool {
	return false
}

func (w *WslExecutor) Name() string {
	if w.available {
		return fmt.Sprintf("wsl2-runtime:%s", w.distro)
	}
	return "wsl2-runtime:unavailable"
}

func (w *WslExecutor) TargetOS() string {
	if w.available {
		return "linux"
	}
	return runtime.GOOS
}

func (w *WslExecutor) TargetArch() string {
	if w.available {
		return "amd64"
	}
	return runtime.GOARCH
}

func (w *WslExecutor) Distro() string {
	return w.distro
}

func (w *WslExecutor) Execute(_ context.Context, _ CommandSpec) (*CommandResult, error) {
	if !w.available {
		return nil, fmt.Errorf("WSL 2 is required for this execution but is unavailable")
	}
	return nil, fmt.Errorf("WSL 2 provides the Linux runtime but does not isolate audit commands; Docker worker isolation is required")
}

func WindowsToWslPath(p string) string {
	if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		drive := strings.ToLower(string(p[0]))
		rest := strings.ReplaceAll(p[2:], "\\", "/")
		if !strings.HasPrefix(rest, "/") {
			rest = "/" + rest
		}
		return "/mnt/" + drive + rest
	}
	return strings.ReplaceAll(p, "\\", "/")
}
