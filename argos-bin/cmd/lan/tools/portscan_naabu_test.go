package tools

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBuildNaabuArgsUsesConnectScanAndExplicitPorts(t *testing.T) {
	got := buildNaabuArgs("192.168.1.10", []int{443, 22})
	want := []string{"-host", "192.168.1.10", "-p", "443,22", "-scan-type", "c", "-silent"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildNaabuArgs() = %v, want %v", got, want)
	}
}

func TestParseNaabuOutputReturnsSortedUniqueValidPorts(t *testing.T) {
	got := parseNaabuOutput("127.0.0.1:443\n127.0.0.1:22\n[::1]:8443\n127.0.0.1:22\nnot-a-port\n127.0.0.1:65536\n")
	want := []int{22, 443, 8443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseNaabuOutput() = %v, want %v", got, want)
	}
}

func TestNormalizeLanPortsDefaultsDeduplicatesAndRejectsInvalidPorts(t *testing.T) {
	got, err := normalizeLanPorts([]int{443, 80, 443})
	if err != nil {
		t.Fatalf("normalizeLanPorts() error = %v", err)
	}
	if want := []int{443, 80}; !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeLanPorts() = %v, want %v", got, want)
	}

	defaults, err := normalizeLanPorts(nil)
	if err != nil {
		t.Fatalf("normalizeLanPorts(nil) error = %v", err)
	}
	if !reflect.DeepEqual(defaults, standardPorts) {
		t.Fatalf("normalizeLanPorts(nil) = %v, want standard ports %v", defaults, standardPorts)
	}

	for _, port := range []int{0, 65536} {
		if _, err := normalizeLanPorts([]int{port}); err == nil {
			t.Errorf("normalizeLanPorts([%d]) accepted an invalid port", port)
		}
	}
}

func TestScanNaabuMapsOpenPortsAndPropagatesCommandErrors(t *testing.T) {
	var gotBinary string
	var gotArgs []string
	runner := func(_ context.Context, binary string, args []string) ([]byte, error) {
		gotBinary = binary
		gotArgs = append([]string(nil), args...)
		return []byte("127.0.0.1:443\n127.0.0.1:22\n127.0.0.1:5555\n"), nil
	}

	got, err := scanNaabu(context.Background(), "naabu", "127.0.0.1", []int{443, 22}, runner)
	if err != nil {
		t.Fatalf("scanNaabu() error = %v", err)
	}
	if gotBinary != "naabu" {
		t.Fatalf("runner binary = %q, want naabu", gotBinary)
	}
	if want := []string{"-host", "127.0.0.1", "-p", "443,22", "-scan-type", "c", "-silent"}; !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("runner args = %v, want %v", gotArgs, want)
	}
	want := []portResult{
		{Port: 22, Protocol: "tcp", Service: "ssh", State: "open"},
		{Port: 443, Protocol: "tcp", Service: "https", State: "open"},
		{Port: 5555, Protocol: "tcp", Service: "unknown", State: "open"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scanNaabu() = %+v, want %+v", got, want)
	}

	_, err = scanNaabu(context.Background(), "naabu", "127.0.0.1", []int{80}, func(context.Context, string, []string) ([]byte, error) {
		return nil, errors.New("scanner failed")
	})
	if err == nil || !strings.Contains(err.Error(), "scanner failed") {
		t.Fatalf("scanNaabu() command error = %v, want wrapped scanner error", err)
	}
}
