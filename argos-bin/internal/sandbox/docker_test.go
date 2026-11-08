package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

func TestDockerRunArgsArePinnedAndContainNoNetworkAccess(t *testing.T) {
	args, err := buildDockerArgs(CommandSpec{
		Path: "/opt/argos/tools/nuclei",
		Dir:  t.TempDir(),
	}, "ghcr.io/argos-auditor/scanner@sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"--pull=never",
		"--network=none",
		"--read-only",
		"--user=65532:65532",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=256",
		"--cpus=2",
		"--tmpfs",
		"dst=/workspace,readonly",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("Docker args missing %q: %s", required, joined)
		}
	}
	if strings.Contains(joined, "--network=host") || strings.Contains(joined, "/var/run/docker.sock") {
		t.Errorf("Docker args contain an unsafe network mode or Docker socket: %s", joined)
	}
}

func TestBrowserWorkerRequiresPackagedSeccompProfile(t *testing.T) {
	t.Setenv("ARGOS_BROWSER_SECCOMP_PROFILE", "")
	spec := CommandSpec{Path: "/usr/local/bin/argos-browser-worker", Dir: t.TempDir()}
	image := "sha256:" + strings.Repeat("a", 64)
	if _, err := buildDockerArgs(spec, image); err == nil {
		t.Fatal("browser worker accepted a missing seccomp profile")
	}
	profile := filepath.Join(t.TempDir(), "chromium-seccomp.json")
	if err := os.WriteFile(profile, []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGOS_BROWSER_SECCOMP_PROFILE", profile)
	args, err := buildDockerArgs(spec, image)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, flag := range []string{"--security-opt=seccomp=" + profile, "--cap-drop=ALL", "--network=none", "--security-opt=no-new-privileges"} {
		if !strings.Contains(joined, flag) {
			t.Errorf("browser worker lost required protection %q", flag)
		}
	}
}

func TestDockerForwardsWorkerRequestOnStdin(t *testing.T) {
	spec := CommandSpec{Path: "/usr/local/bin/argos-worker-probe", Dir: t.TempDir(), Stdin: `{}`}
	image := "sha256:" + strings.Repeat("a", 64)
	args, err := buildDockerArgs(spec, image)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "--interactive") {
		t.Fatal("Docker would discard the worker request without interactive stdin")
	}
	spec.Stdin = ""
	args, err = buildDockerArgs(spec, image)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, " "), "--interactive") {
		t.Fatal("scanner with no request unexpectedly keeps stdin open")
	}
}

func TestDockerReadOnlyMountsAlsoMakeSubmountsReadOnly(t *testing.T) {
	toolsDir := filepath.Join(t.TempDir(), "argos-tools")
	t.Setenv("ARGOS_TOOLS_DIR", toolsDir)
	args, err := buildDockerArgs(CommandSpec{
		Path: filepath.Join(toolsDir, "nuclei", "nuclei"),
		Dir:  t.TempDir(),
	}, "ghcr.io/argos-auditor/scanner@sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, mount := range []string{
		"dst=/workspace,readonly,bind-recursive=readonly,bind-propagation=rprivate",
		"dst=/opt/argos/tools,readonly,bind-recursive=readonly,bind-propagation=rprivate",
	} {
		if !strings.Contains(joined, mount) {
			t.Errorf("read-only bind mount is not recursively read-only (%q): %s", mount, joined)
		}
	}
}

func TestDockerRunArgsWithCIDFileAddsTheOptionBeforeTheImage(t *testing.T) {
	args := dockerRunArgsWithCIDFile([]string{"run", "--rm", "image@sha256:" + strings.Repeat("a", 64), "scanner"}, "C:/tmp/container.cid")
	if len(args) < 5 || args[0] != "run" || args[1] != "--cidfile" || args[2] != "C:/tmp/container.cid" {
		t.Fatalf("cidfile option was not inserted after run: %v", args)
	}
	if args[3] != "--rm" || !strings.HasPrefix(args[4], "image@sha256:") {
		t.Fatalf("Docker run options or image were reordered: %v", args)
	}
}

func TestCleanupDockerContainerUsesOnlyAValidCID(t *testing.T) {
	cidFile := filepath.Join(t.TempDir(), "container.cid")
	id := strings.Repeat("a", 64)
	if err := os.WriteFile(cidFile, []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed := ""
	err := cleanupDockerContainer(context.Background(), cidFile, func(_ context.Context, containerID string) error {
		removed = containerID
		return nil
	})
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if removed != id {
		t.Fatalf("removed container ID = %q, want %q", removed, id)
	}
	if err := os.WriteFile(cidFile, []byte("--force; unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed = ""
	if err := cleanupDockerContainer(context.Background(), cidFile, func(_ context.Context, containerID string) error {
		removed = containerID
		return nil
	}); err == nil {
		t.Fatal("malformed container ID was accepted")
	}
	if removed != "" {
		t.Fatalf("malformed container ID reached the remover: %q", removed)
	}
}

func TestDockerRunArgsMountOnlyTheToolCacheAndTranslateScannerPaths(t *testing.T) {
	toolsDir := filepath.Join(t.TempDir(), "argos-tools")
	toolPath := filepath.Join(toolsDir, "nuclei", "nuclei")
	if err := os.MkdirAll(filepath.Dir(toolPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toolPath, []byte("scanner"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGOS_TOOLS_DIR", toolsDir)
	args, err := buildDockerArgs(CommandSpec{
		Path: toolPath,
		Dir:  t.TempDir(),
		Args: []string{"--config=" + filepath.Join(toolsDir, "nuclei", "config.yaml")},
	}, "ghcr.io/argos-auditor/scanner@sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "dst=/opt/argos/tools,readonly") {
		t.Fatalf("scanner cache is not mounted read-only: %s", joined)
	}
	if !strings.Contains(joined, "/opt/argos/tools/nuclei/nuclei") || !strings.Contains(joined, "--config=/opt/argos/tools/nuclei/config.yaml") {
		t.Fatalf("host scanner paths were not translated into the worker: %s", joined)
	}
	imageArgument := strings.Index(joined, "ghcr.io/argos-auditor/scanner@sha256:")
	if imageArgument < 0 || strings.Contains(joined[imageArgument:], toolsDir) {
		t.Fatalf("host tool-cache path leaked into worker command arguments: %s", joined)
	}
}

func TestDockerRunArgsMountsPrivateArtifactsAndTranslatesBothPaths(t *testing.T) {
	sourceDir := t.TempDir()
	artifactDir := t.TempDir()
	args, err := buildDockerArgs(CommandSpec{
		Path:        "/opt/argos/tools/gitleaks",
		Dir:         sourceDir,
		ArtifactDir: artifactDir,
		Args: []string{
			"detect",
			"--source", sourceDir,
			"--report-path", filepath.Join(artifactDir, "report.json"),
		},
	}, "ghcr.io/argos-auditor/scanner@sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"dst=/workspace,readonly",
		"dst=/artifacts",
		"--source /workspace",
		"--report-path /artifacts/report.json",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("Docker args missing %q: %s", required, joined)
		}
	}
}

func TestDockerRunArgsRejectArtifactDirectoriesOverlappingTheSource(t *testing.T) {
	root := t.TempDir()
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := buildDockerArgs(CommandSpec{
		Path:        "/opt/argos/tools/gitleaks",
		Dir:         root,
		ArtifactDir: artifacts,
	}, "ghcr.io/argos-auditor/scanner@sha256:"+strings.Repeat("b", 64))
	if err == nil {
		t.Fatal("an artifact mount inside the read-only source tree must be rejected")
	}
}

func TestDockerRunArgsRejectCommaInHostMountPaths(t *testing.T) {
	root := t.TempDir()
	image := "ghcr.io/argos-auditor/scanner@sha256:" + strings.Repeat("a", 64)

	t.Run("source", func(t *testing.T) {
		source := filepath.Join(root, "source,readonly=false")
		if err := os.Mkdir(source, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := buildDockerArgs(CommandSpec{Path: "/opt/argos/tools/nuclei", Dir: source}, image)
		if err == nil {
			t.Fatal("source mount path containing a comma was accepted")
		}
	})

	t.Run("scanner cache", func(t *testing.T) {
		toolsDir := filepath.Join(root, "tools,readonly=false")
		if err := os.MkdirAll(filepath.Join(toolsDir, "nuclei"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ARGOS_TOOLS_DIR", toolsDir)
		_, err := buildDockerArgs(CommandSpec{
			Path: filepath.Join(toolsDir, "nuclei", "nuclei"),
			Dir:  t.TempDir(),
		}, image)
		if err == nil {
			t.Fatal("scanner cache mount path containing a comma was accepted")
		}
	})

	t.Run("artifact directory", func(t *testing.T) {
		artifacts := filepath.Join(root, "artifacts,readonly=false")
		if err := os.Mkdir(artifacts, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := buildDockerArgs(CommandSpec{
			Path:        "/opt/argos/tools/nuclei",
			Dir:         t.TempDir(),
			ArtifactDir: artifacts,
		}, image)
		if err == nil {
			t.Fatal("artifact mount path containing a comma was accepted")
		}
	})

	t.Run("gateway socket", func(t *testing.T) {
		_, err := buildDockerArgsWithGateway(CommandSpec{
			Path:        "/usr/local/bin/nuclei",
			Dir:         t.TempDir(),
			NetworkMode: "scope-gateway",
			SessionID:   "ses_comma_mount",
			OperationID: "op_comma_mount",
			Scope:       &scope.ScopeConfig{AllowedDomains: []string{"app.example.test"}},
		}, image, filepath.Join(root, "gateway,dst=/tmp/gateway.sock"))
		if err == nil {
			t.Fatal("gateway mount path containing a comma was accepted")
		}
	})
}

func TestDockerRunArgsRejectUnpinnedImagesAndNetworkModes(t *testing.T) {
	tests := []struct {
		name  string
		spec  CommandSpec
		image string
	}{
		{name: "tagged image", spec: CommandSpec{Path: "/opt/argos/tools/nuclei"}, image: "argos/scanner:latest"},
		{name: "host network", spec: CommandSpec{Path: "/opt/argos/tools/nuclei", NetworkMode: "host"}, image: "argos/scanner@sha256:" + strings.Repeat("b", 64)},
		{name: "bridge network", spec: CommandSpec{Path: "/opt/argos/tools/nuclei", NetworkMode: "bridge"}, image: "argos/scanner@sha256:" + strings.Repeat("b", 64)},
		{name: "host binary path", spec: CommandSpec{Path: filepath.Join(os.TempDir(), "nuclei")}, image: "argos/scanner@sha256:" + strings.Repeat("b", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildDockerArgs(tt.spec, tt.image)
			if err == nil {
				t.Fatal("expected unsafe runtime configuration to be rejected")
			}
		})
	}
}

func TestDigestPinnedImageAcceptsImmutableLocalImageIDs(t *testing.T) {
	imageID := "sha256:" + strings.Repeat("c", 64)
	if !isDigestPinnedImage(imageID) {
		t.Fatalf("Docker image ID %q must be accepted as an immutable local image reference", imageID)
	}
	if !isDigestPinnedImage("ghcr.io/argos-auditor/worker@" + imageID) {
		t.Fatal("registry digest reference must remain accepted")
	}
	if isDigestPinnedImage("ghcr.io/argos-auditor/worker:1.2.3") {
		t.Fatal("mutable image tags must remain rejected")
	}
}

func TestDockerGatewayArgsKeepWorkerOfflineAndRouteProxyThroughPrivateSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "gateway.sock")
	args, err := buildDockerArgsWithGateway(CommandSpec{
		Path:        "/usr/local/bin/nuclei",
		Dir:         t.TempDir(),
		NetworkMode: "scope-gateway",
		SessionID:   "ses_gateway_worker",
		OperationID: "call_gateway_worker",
		Scope:       &scope.ScopeConfig{AllowedDomains: []string{"app.example.test"}},
	}, "ghcr.io/argos-auditor/scanner@sha256:"+strings.Repeat("e", 64), socket)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"--network=none",
		"dst=/run/argos/gateway.sock",
		"/usr/local/bin/argos-worker-relay",
		"--gateway-socket /run/argos/gateway.sock -- /usr/local/bin/nuclei",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("gateway Docker args missing %q: %s", required, joined)
		}
	}
	if strings.Contains(joined, "--network=host") || strings.Contains(joined, "/var/run/docker.sock") {
		t.Fatalf("gateway worker has a direct host network path: %s", joined)
	}
}

func TestDockerGatewayRejectsMissingControllerMetadata(t *testing.T) {
	_, err := buildDockerArgsWithGateway(CommandSpec{
		Path:        "/usr/local/bin/nuclei",
		Dir:         t.TempDir(),
		NetworkMode: "scope-gateway",
	}, "ghcr.io/argos-auditor/scanner@sha256:"+strings.Repeat("f", 64), filepath.Join(t.TempDir(), "gateway.sock"))
	if err == nil || !strings.Contains(err.Error(), "controller session") {
		t.Fatalf("gateway without a controller-bound scope was not rejected: %v", err)
	}
}

func TestDockerRequiredFailsClosed(t *testing.T) {
	for _, mode := range []string{"default", "unavailable", "launch-failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("PATH", t.TempDir())
			var executor Executor
			scannerPath := ""
			if mode == "default" {
				executor = DefaultExecutor()
				if docker, ok := executor.(*DockerExecutor); ok {
					docker.dockerAvailable = false
					docker.image = ""
				}
			} else {
				docker := NewDockerExecutor()
				if mode == "launch-failure" {
					docker.dockerAvailable = true
					docker.image = "argos/scanner@sha256:" + strings.Repeat("d", 64)
					scannerPath = "/opt/argos/tools/test"
				}
				executor = docker
			}
			program, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if scannerPath == "" {
				scannerPath = program
			}
			marker := filepath.Join(t.TempDir(), "host-executed")
			result, err := executor.Execute(context.Background(), CommandSpec{
				Path: scannerPath,
				Args: []string{"-test.run=^TestSandboxHostFallbackHelper$"},
				Env:  []string{"ARGOS_SANDBOX_TEST_MARKER=" + marker},
			})
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Errorf("audit command ran on host: %v", statErr)
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "docker") {
				t.Errorf("expected an explicit Docker error, got result=%+v error=%v", result, err)
			}
			if result != nil {
				t.Errorf("blocked execution returned a command result: %+v", result)
			}
			if executor.Name() != "docker" {
				t.Errorf("default audit executor must require Docker, got %q", executor.Name())
			}
		})
	}
}

func TestSandboxHostFallbackHelper(t *testing.T) {
	marker := os.Getenv("ARGOS_SANDBOX_TEST_MARKER")
	if marker == "" {
		return
	}
	if err := os.WriteFile(marker, []byte("executed"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDockerArgsRejectInvalidMemoryLimits(t *testing.T) {
	_, err := buildDockerArgs(CommandSpec{Path: "/opt/argos/tools/nuclei", MemoryLimit: "1g;--privileged"}, "argos/scanner@sha256:"+strings.Repeat("c", 64))
	if err == nil {
		t.Fatal("expected invalid memory limit to be rejected")
	}
}
