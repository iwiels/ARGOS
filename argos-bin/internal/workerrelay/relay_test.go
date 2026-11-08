package workerrelay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const helperEnv = "ARGOS_WORKER_RELAY_TEST_HELPER"

func TestRunRoutesChildHTTPProxyTrafficThroughUnixSocket(t *testing.T) {
	directory, err := os.MkdirTemp("", "agw")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socketPath := filepath.Join(directory, "gw.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requestLine := make(chan string, 1)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			serverDone <- err
			return
		}
		requestLine <- strings.TrimSpace(line)
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		serverDone <- err
	}()

	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = run(
		ctx,
		socketPath,
		[]string{binary, "-test.run=^TestWorkerRelayChildHelper$"},
		nil,
		io.Discard,
		io.Discard,
		[]string{helperEnv + "=1"},
	)
	if err != nil {
		t.Fatalf("worker relay command failed: %v", err)
	}
	select {
	case line := <-requestLine:
		if line != "GET http://gateway.test/scope-check HTTP/1.1" {
			t.Fatalf("gateway received request line %q", line)
		}
	case <-ctx.Done():
		t.Fatal("worker request did not reach the Unix gateway")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestWorkerRelayChildHelper(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	response, err := http.Get("http://gateway.test/scope-check")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(31)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "status %d", response.StatusCode)
		os.Exit(32)
	}
	os.Exit(0)
}

func TestProxyEnvironmentOverridesInheritedProxyAndBypassSettings(t *testing.T) {
	env := proxyEnvironment([]string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://attacker.invalid:8080",
		"ARGOS_WORKER_PROXY_URL=http://127.0.0.1:6666",
		"NO_PROXY=*.corp.local",
	}, "http://127.0.0.1:12345")
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "attacker.invalid") || strings.Contains(joined, "*.corp.local") || strings.Contains(joined, "127.0.0.1:6666") {
		t.Fatalf("inherited proxy configuration survived: %s", joined)
	}
	for _, expected := range []string{"HTTP_PROXY=http://127.0.0.1:12345", "HTTPS_PROXY=http://127.0.0.1:12345", "NO_PROXY="} {
		if !strings.Contains(joined, expected) {
			t.Errorf("proxy environment missing %q: %s", expected, joined)
		}
	}
	if count := strings.Count(joined, "ARGOS_WORKER_PROXY_URL=http://127.0.0.1:12345"); count != 1 {
		t.Fatalf("worker proxy setting count = %d, want one runtime-owned value: %s", count, joined)
	}
}

func TestRunRequiresGatewayAndCommand(t *testing.T) {
	if err := run(context.Background(), "", []string{"true"}, nil, io.Discard, io.Discard, nil); err == nil {
		t.Fatal("expected missing gateway socket to be rejected")
	}
	if err := run(context.Background(), "/tmp/gateway.sock", nil, nil, io.Discard, io.Discard, nil); err == nil {
		t.Fatal("expected missing command to be rejected")
	}
}
