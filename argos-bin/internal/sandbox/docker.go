package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/gateway"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
	"github.com/iwiels/argos-auditor/argos-bin/internal/traffic"
)

type DockerExecutor struct {
	dockerAvailable bool
	imageAvailable  bool
	image           string
}

func NewDockerExecutor() *DockerExecutor {
	d := &DockerExecutor{image: strings.TrimSpace(os.Getenv("ARGOS_SANDBOX_IMAGE"))}
	d.checkAvailability()
	return d
}

func (d *DockerExecutor) checkAvailability() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	d.dockerAvailable = cmd.Run() == nil
	if !d.dockerAvailable || !isDigestPinnedImage(d.image) {
		return
	}
	inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer inspectCancel()
	inspect := exec.CommandContext(inspectCtx, "docker", "image", "inspect", "--format", "{{.Id}}", d.image)
	output, err := inspect.Output()
	d.imageAvailable = err == nil && strings.TrimSpace(string(output)) != ""
}

func (d *DockerExecutor) IsAvailable() bool {
	return d.dockerAvailable && d.imageAvailable && isDigestPinnedImage(d.image)
}

func (d *DockerExecutor) IsSandboxed() bool {
	return d.IsAvailable()
}

func (d *DockerExecutor) Name() string {
	return "docker"
}

func (d *DockerExecutor) Execute(ctx context.Context, spec CommandSpec) (*CommandResult, error) {
	if !d.dockerAvailable {
		return nil, fmt.Errorf("Docker is required for audit execution but is unavailable")
	}
	if !isDigestPinnedImage(d.image) {
		return nil, fmt.Errorf("ARGOS_SANDBOX_IMAGE must name a scanner image pinned by sha256 digest")
	}
	if !d.imageAvailable {
		return nil, fmt.Errorf("Docker scanner worker image %q is not present locally; install the matching Argos worker package before scanning", d.image)
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var guard *scope.ScopeGuard
	var gatewayServer *gateway.UnixServer
	var gatewaySocket string
	var err error
	if spec.NetworkMode == "scope-gateway" {
		if spec.Scope == nil || spec.SessionID == "" || spec.OperationID == "" {
			return nil, fmt.Errorf("scope gateway requires controller session, operation, and scope metadata")
		}
		config := *spec.Scope
		config.SessionID = spec.SessionID
		config.OperationID = spec.OperationID
		if config.AuditLogDir == "" {
			config.AuditLogDir, err = operationAuditDirectory(spec.SessionID, spec.OperationID)
			if err != nil {
				return nil, err
			}
		}
		guard, err = scope.New(config)
		if err != nil {
			return nil, fmt.Errorf("create session scope gateway: %w", err)
		}
		defer guard.Close()

		gatewayDir, err := os.MkdirTemp("", "argos-scope-gateway-")
		if err != nil {
			return nil, fmt.Errorf("create private gateway socket directory: %w", err)
		}
		defer os.RemoveAll(gatewayDir)
		gatewaySocket = filepath.Join(gatewayDir, "gateway.sock")
		capture := gateway.CaptureConfig{}
		if traffic.CaptureEnabled() {
			traffic.WarnCaptureEnabled()
			capture = gateway.CaptureConfig{
				Store:      traffic.NewStore(""),
				SessionID:  spec.SessionID,
				SourceTool: filepath.Base(spec.Path),
			}
		}
		gatewayServer, err = gateway.ListenUnix(cctx, gatewaySocket, gateway.NewHandler(guard, capture))
		if err != nil {
			return nil, fmt.Errorf("start session scope gateway: %w", err)
		}
		defer gatewayServer.Close()
	}

	workerUser, err := dockerWorkerUser()
	if err != nil {
		return nil, err
	}
	dockerArgs, err := buildDockerArgsWithRuntime(spec, d.image, gatewaySocket, workerUser)
	if err != nil {
		return nil, err
	}
	cidDir, err := os.MkdirTemp("", "argos-docker-cid-")
	if err != nil {
		return nil, fmt.Errorf("create private Docker container ID directory: %w", err)
	}
	defer os.RemoveAll(cidDir)
	cidFile := filepath.Join(cidDir, "container.cid")
	dockerArgs = dockerRunArgsWithCIDFile(dockerArgs, cidFile)
	cmd := exec.CommandContext(cctx, "docker", dockerArgs...)
	if spec.Stdin != "" {
		cmd.Stdin = strings.NewReader(spec.Stdin)
	}

	maxOut := spec.MaxOut
	if maxOut <= 0 {
		maxOut = 1 << 20
	}
	outBuf := newBoundedBuffer(maxOut)
	errBuf := newBoundedBuffer(65536)
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	start := time.Now()
	err = cmd.Run()
	duration := time.Since(start)
	var cleanupErr error
	if cctx.Err() != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupErr = cleanupDockerContainer(cleanupCtx, cidFile, func(ctx context.Context, containerID string) error {
			remove := exec.CommandContext(ctx, "docker", "rm", "--force", containerID)
			output, err := remove.CombinedOutput()
			if err != nil {
				return fmt.Errorf("docker rm --force failed: %w: %s", err, strings.TrimSpace(string(output)))
			}
			return nil
		})
		cleanupCancel()
	}

	if err != nil && cmd.ProcessState == nil {
		return nil, fmt.Errorf("Docker audit execution could not start: %w", err)
	}

	out := outBuf.String()
	errOut := errBuf.String()
	if cleanupErr != nil {
		errOut = strings.TrimSpace(errOut + "\nfailed to remove canceled audit container: " + cleanupErr.Error())
	}

	exit := 0
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}
	if exit == 125 {
		return nil, fmt.Errorf("Docker could not create the isolated audit worker: %s", strings.TrimSpace(errOut))
	}

	return &CommandResult{
		Stdout:          out,
		Stderr:          errOut,
		ExitCode:        exit,
		TimedOut:        cctx.Err() == context.DeadlineExceeded,
		Duration:        duration,
		Sandboxed:       true,
		OutputTruncated: outBuf.Truncated(),
		StderrTruncated: errBuf.Truncated(),
	}, nil
}

func dockerRunArgsWithCIDFile(args []string, cidFile string) []string {
	if len(args) == 0 {
		return nil
	}
	result := make([]string, 0, len(args)+2)
	result = append(result, args[0], "--cidfile", cidFile)
	return append(result, args[1:]...)
}

func cleanupDockerContainer(ctx context.Context, cidFile string, remove func(context.Context, string) error) error {
	data, err := os.ReadFile(cidFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Docker container ID: %w", err)
	}
	id := strings.TrimSpace(string(data))
	if len(id) < 12 || len(id) > 64 || len(id)%2 != 0 {
		return fmt.Errorf("Docker wrote an invalid container ID")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("Docker wrote an invalid container ID")
	}
	if remove == nil {
		return fmt.Errorf("Docker container removal is unavailable")
	}
	return remove(ctx, id)
}

func buildDockerArgs(spec CommandSpec, image string) ([]string, error) {
	return buildDockerArgsWithGateway(spec, image, "")
}

func buildDockerArgsWithGateway(spec CommandSpec, image, gatewaySocket string) ([]string, error) {
	return buildDockerArgsWithRuntime(spec, image, gatewaySocket, "65532:65532")
}

func buildDockerArgsWithRuntime(spec CommandSpec, image, gatewaySocket, workerUser string) ([]string, error) {
	if !isDigestPinnedImage(image) {
		return nil, fmt.Errorf("scanner image must be pinned by sha256 digest")
	}
	if !isUnprivilegedUser(workerUser) {
		return nil, fmt.Errorf("scanner worker must run as a numeric non-root user")
	}
	networkMode := spec.NetworkMode
	if networkMode == "" {
		networkMode = "none"
	}
	if networkMode != "none" && networkMode != "scope-gateway" {
		return nil, fmt.Errorf("audit workers require --network=none with an optional scope gateway; network mode %q is blocked", networkMode)
	}
	if networkMode == "scope-gateway" && (gatewaySocket == "" || spec.Scope == nil || spec.SessionID == "" || spec.OperationID == "") {
		return nil, fmt.Errorf("scope gateway requires a socket and controller session, operation, and scope metadata")
	}
	if networkMode == "scope-gateway" {
		if err := validateDockerMountSource(gatewaySocket, "scope gateway socket"); err != nil {
			return nil, err
		}
	}
	containerScannerPath := path.Clean(spec.Path)
	toolsDir := ""
	if !isContainerScannerPath(spec.Path) {
		var err error
		toolsDir, err = resolvedToolsDirectory()
		if err != nil {
			return nil, err
		}
		if err := validateDockerMountSource(toolsDir, "scanner cache"); err != nil {
			return nil, err
		}
		var mapped bool
		containerScannerPath, mapped = mapHostPathToContainer(spec.Path, toolsDir, "/opt/argos/tools")
		if !mapped {
			return nil, fmt.Errorf("scanner path %q is neither in the worker image nor inside ARGOS_TOOLS_DIR", spec.Path)
		}
	}

	memLimit := spec.MemoryLimit
	if memLimit == "" {
		memLimit = "1g"
	}
	if !isDockerMemoryLimit(memLimit) {
		return nil, fmt.Errorf("invalid Docker memory limit %q", memLimit)
	}

	dir := spec.Dir
	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve audit source directory: %w", err)
	}
	if err := validateDockerMountSource(absDir, "audit source"); err != nil {
		return nil, err
	}
	if absDir == string(filepath.Separator) {
		return nil, fmt.Errorf("refusing to mount the filesystem root as audit source")
	}
	if info, statErr := os.Stat(absDir); statErr != nil || !info.IsDir() {
		if statErr != nil {
			return nil, fmt.Errorf("audit source directory is unavailable: %w", statErr)
		}
		return nil, fmt.Errorf("audit source path is not a directory")
	}
	artifactDir := ""
	if spec.ArtifactDir != "" {
		artifactDir, err = filepath.Abs(spec.ArtifactDir)
		if err != nil {
			return nil, fmt.Errorf("resolve audit artifact directory: %w", err)
		}
		if err := validateDockerMountSource(artifactDir, "audit artifact"); err != nil {
			return nil, err
		}
		artifactInfo, statErr := os.Lstat(artifactDir)
		if statErr != nil || !artifactInfo.IsDir() || artifactInfo.Mode()&os.ModeSymlink != 0 {
			if statErr != nil {
				return nil, fmt.Errorf("audit artifact directory is unavailable: %w", statErr)
			}
			return nil, fmt.Errorf("audit artifact path must be a real directory")
		}
		if artifactDir == string(filepath.Separator) || pathsOverlap(absDir, artifactDir) {
			return nil, fmt.Errorf("audit artifact directory must be outside the read-only source tree")
		}
		if toolsDir != "" && pathsOverlap(toolsDir, artifactDir) {
			return nil, fmt.Errorf("audit artifact directory must be outside the read-only scanner cache")
		}
	}

	dockerArgs := []string{
		"run",
		"--rm",
		"--pull=never",
		"--init",
		"--read-only",
		"--network=none",
		fmt.Sprintf("--user=%s", workerUser),
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=256",
		"--cpus=2",
		fmt.Sprintf("--memory=%s", memLimit),
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
		"--mount", fmt.Sprintf("type=bind,src=%s,dst=/workspace,readonly,bind-recursive=readonly,bind-propagation=rprivate", absDir),
		"-w", "/workspace",
		"-e", "HOME=/tmp",
		"-e", "TMPDIR=/tmp",
	}
	if spec.Stdin != "" {
		dockerArgs = append(dockerArgs, "--interactive")
	}
	if toolsDir != "" {
		dockerArgs = append(dockerArgs, "--mount", fmt.Sprintf("type=bind,src=%s,dst=/opt/argos/tools,readonly,bind-recursive=readonly,bind-propagation=rprivate", toolsDir))
	}
	if containerScannerPath == "/usr/local/bin/argos-browser-worker" {
		profile := strings.TrimSpace(os.Getenv("ARGOS_BROWSER_SECCOMP_PROFILE"))
		info, err := os.Stat(profile)
		if profile == "" || err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("browser worker requires the packaged Chromium seccomp profile")
		}
		dockerArgs = append(dockerArgs, "--security-opt=seccomp="+profile)
	}
	if artifactDir != "" {
		dockerArgs = append(dockerArgs, "--mount", fmt.Sprintf("type=bind,src=%s,dst=/artifacts,rw", artifactDir))
	}
	if networkMode == "scope-gateway" {
		dockerArgs = append(dockerArgs, "--mount", fmt.Sprintf("type=bind,src=%s,dst=/run/argos/gateway.sock", gatewaySocket))
	}
	for _, e := range spec.Env {
		dockerArgs = append(dockerArgs, "-e", translateMountedPath(e, absDir, toolsDir, artifactDir))
	}
	dockerArgs = append(dockerArgs, image)
	if networkMode == "scope-gateway" {
		dockerArgs = append(dockerArgs, "/usr/local/bin/argos-worker-relay", "--gateway-socket", "/run/argos/gateway.sock", "--", containerScannerPath)
	} else {
		dockerArgs = append(dockerArgs, containerScannerPath)
	}
	for _, arg := range spec.Args {
		dockerArgs = append(dockerArgs, translateMountedPath(arg, absDir, toolsDir, artifactDir))
	}
	return dockerArgs, nil
}

func operationAuditDirectory(sessionID, operationID string) (string, error) {
	root := strings.TrimSpace(os.Getenv("ARGOS_AUDIT_LOG_DIR"))
	if root == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve audit log directory: %w", err)
		}
		root = filepath.Join(configDir, "argos", "audit")
	}
	digest := sha256.Sum256([]byte(sessionID + "\x00" + operationID))
	return filepath.Join(root, hex.EncodeToString(digest[:]), "worker"), nil
}

func resolvedToolsDirectory() (string, error) {
	toolsDir := strings.TrimSpace(os.Getenv("ARGOS_TOOLS_DIR"))
	if toolsDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve scanner cache directory: %w", err)
		}
		toolsDir = filepath.Join(home, ".argos", "tools")
	}
	abs, err := filepath.Abs(toolsDir)
	if err != nil {
		return "", fmt.Errorf("resolve scanner cache directory: %w", err)
	}
	return filepath.Clean(abs), nil
}

func mapHostPathToContainer(hostPath, hostRoot, containerRoot string) (string, bool) {
	if !filepath.IsAbs(hostPath) {
		return "", false
	}
	absPath, err := filepath.Abs(hostPath)
	if err != nil {
		return "", false
	}
	relative, err := filepath.Rel(hostRoot, absPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	if relative == "." {
		return containerRoot, true
	}
	return path.Join(containerRoot, filepath.ToSlash(relative)), true
}

func translateMountedPath(value, sourceRoot, toolsRoot, artifactRoot string) string {
	name, argument, hasName := strings.Cut(value, "=")
	if hasName && !strings.HasPrefix(name, "-") {
		return value
	}
	for _, mount := range []struct {
		hostRoot      string
		containerRoot string
	}{{sourceRoot, "/workspace"}, {toolsRoot, "/opt/argos/tools"}, {artifactRoot, "/artifacts"}} {
		if mount.hostRoot == "" {
			continue
		}
		target := value
		if hasName {
			target = argument
		}
		if mapped, ok := mapHostPathToContainer(target, mount.hostRoot, mount.containerRoot); ok {
			if hasName {
				return name + "=" + mapped
			}
			return mapped
		}
	}
	return value
}

func pathsOverlap(left, right string) bool {
	contains := func(parent, candidate string) bool {
		relative, err := filepath.Rel(parent, candidate)
		return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
	}
	return contains(left, right) || contains(right, left)
}

func validateDockerMountSource(path, name string) error {
	if strings.Contains(path, ",") {
		return fmt.Errorf("Docker %s mount path contains an unsupported comma", name)
	}
	return nil
}

func isUnprivilegedUser(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	uid, uidErr := strconv.ParseUint(parts[0], 10, 32)
	gid, gidErr := strconv.ParseUint(parts[1], 10, 32)
	return uidErr == nil && gidErr == nil && uid > 0 && gid > 0
}

func dockerWorkerUser() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolve an unprivileged Docker worker identity: %w", err)
	}
	identity := current.Uid + ":" + current.Gid
	if !isUnprivilegedUser(identity) {
		return "", fmt.Errorf("Docker audit workers require Argos to run as a non-root Linux user")
	}
	return identity, nil
}

func isDigestPinnedImage(image string) bool {
	if strings.HasPrefix(image, "sha256:") {
		return isSHA256Digest(strings.TrimPrefix(image, "sha256:"))
	}
	separator := strings.LastIndex(image, "@sha256:")
	if separator <= 0 {
		return false
	}
	digest := image[separator+len("@sha256:"):]
	return isSHA256Digest(digest)
}

func isSHA256Digest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func isContainerScannerPath(scannerPath string) bool {
	if !path.IsAbs(scannerPath) {
		return false
	}
	clean := path.Clean(scannerPath)
	for _, prefix := range []string{"/opt/argos/tools/", "/usr/local/bin/", "/usr/bin/", "/bin/"} {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

func isDockerMemoryLimit(limit string) bool {
	index := 0
	for index < len(limit) && limit[index] >= '0' && limit[index] <= '9' {
		index++
	}
	if index == 0 {
		return false
	}
	amount, err := strconv.ParseUint(limit[:index], 10, 64)
	if err != nil || amount == 0 {
		return false
	}
	unit := strings.ToLower(limit[index:])
	return unit == "" || unit == "b" || unit == "k" || unit == "m" || unit == "g"
}

func (d *DockerExecutor) TargetOS() string    { return "linux" }
func (d *DockerExecutor) TargetArch() string  { return runtime.GOARCH }
func (d *DockerExecutor) WorkerImage() string { return d.image }
