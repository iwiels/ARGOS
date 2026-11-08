package tools

import (
	"strings"
	"testing"
)

func TestTargetExecutableNameFor(t *testing.T) {
	tests := []struct {
		name string
		goos string
		kind string
		want string
	}{
		{name: "linux binary", goos: "linux", kind: "binary", want: "web"},
		{name: "windows binary", goos: "windows", kind: "binary", want: "web.exe"},
		{name: "source script", goos: "windows", kind: "source", want: "sqlmap.py"},
		{name: "templates", goos: "linux", kind: "templates", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := &BinarySpec{Bin: "web", Kind: test.kind}
			if test.kind == "source" {
				spec.Bin = "sqlmap.py"
			}
			if got := spec.TargetExecutableNameFor(test.goos); got != test.want {
				t.Fatalf("TargetExecutableNameFor(%q) = %q, want %q", test.goos, got, test.want)
			}
		})
	}
}

func TestSelectArchiveAssetForLinuxArchitecture(t *testing.T) {
	spec := &BinarySpec{Name: "nuclei", Version: "v3.11.0", Archive: "zip"}
	assets := []string{"nuclei_v3.11.0_linux_amd64.zip", "nuclei_v3.11.0_linux_arm64.zip"}
	byName := map[string]string{assets[0]: "https://example.test/amd64", assets[1]: "https://example.test/arm64"}

	got, err := selectArchiveAssetFor(assets, byName, spec, "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if got != assets[1] {
		t.Fatalf("selected %q, want %q", got, assets[1])
	}
}

func TestSelectArchiveAssetForReportsUnsupportedArchitecture(t *testing.T) {
	spec := &BinarySpec{
		Name: "codeql", Repo: "github/codeql-cli-binaries", Version: "v2.20.7", Archive: "zip",
		AssetTemplate:  "codeql-{platform}.zip",
		AssetPlatforms: map[string]string{"linux": "linux64"},
		AssetArch:      "amd64",
	}
	_, err := selectArchiveAssetFor([]string{"codeql-linux64.zip"}, map[string]string{"codeql-linux64.zip": "https://example.test/codeql"}, spec, "linux", "arm64")
	if err == nil {
		t.Fatal("expected an unsupported architecture error")
	}
	for _, want := range []string{"linux/arm64", "codeql", "v2.20.7"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not identify %q", err, want)
		}
	}
}
func TestSelectArchiveAssetForNaabuRejectsLinuxArm64(t *testing.T) {
	var spec *BinarySpec
	for i := range binSpecs {
		if binSpecs[i].Name == "naabu" {
			spec = &binSpecs[i]
			break
		}
	}
	if spec == nil {
		t.Fatal("pinned Naabu spec is missing")
	}
	assets := []string{"naabu_2.3.1_linux_amd64.zip", "naabu_2.3.1_linux_arm64.zip"}
	byName := map[string]string{
		assets[0]: "https://example.test/naabu-amd64",
		assets[1]: "https://example.test/naabu-arm64",
	}
	_, err := selectArchiveAssetFor(assets, byName, spec, "linux", "arm64")
	if err == nil {
		t.Fatal("selected a Linux arm64 artifact for pinned Naabu v2.3.1")
	}
	for _, want := range []string{"linux/arm64", "naabu", "v2.3.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not identify %q", err, want)
		}
	}
}
func TestSelectArchiveAssetForNaabuPreservesMacArm64(t *testing.T) {
	var spec *BinarySpec
	for i := range binSpecs {
		if binSpecs[i].Name == "naabu" {
			spec = &binSpecs[i]
			break
		}
	}
	if spec == nil {
		t.Fatal("pinned Naabu spec is missing")
	}
	assets := []string{"naabu_2.3.1_darwin_amd64.zip", "naabu_2.3.1_darwin_arm64.zip"}
	byName := map[string]string{
		assets[0]: "https://example.test/naabu-amd64",
		assets[1]: "https://example.test/naabu-arm64",
	}
	got, err := selectArchiveAssetFor(assets, byName, spec, "darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if got != assets[1] {
		t.Fatalf("selected %q, want native macOS arm64 asset %q", got, assets[1])
	}
}
