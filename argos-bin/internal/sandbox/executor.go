package sandbox

import (
	"context"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

type CommandSpec struct {
	Path        string
	Args        []string
	Dir         string
	ArtifactDir string
	Env         []string
	Stdin       string
	Timeout     time.Duration
	MaxOut      int
	NetworkMode string // "none", "host", or bridge
	MemoryLimit string // e.g. "1g"
	CpuLimit    string
	TmpDir      string
	ProxySocket string
	Strict      bool
	SessionID   string
	OperationID string
	Scope       *scope.ScopeConfig
}

type CommandResult struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	TimedOut        bool
	Duration        time.Duration
	Sandboxed       bool
	OutputTruncated bool
	StderrTruncated bool
}

type Executor interface {
	Execute(ctx context.Context, spec CommandSpec) (*CommandResult, error)
	IsSandboxed() bool
	Name() string
}

func DefaultExecutor() Executor {
	return NewDockerExecutor()
}
