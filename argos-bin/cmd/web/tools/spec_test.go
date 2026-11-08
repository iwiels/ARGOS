package tools

import "testing"

func TestTargetExecutableName_Templates(t *testing.T) {
	spec := &BinarySpec{Name: "nuclei-templates", Bin: "nuclei-templates", Kind: "templates"}
	if got := spec.TargetExecutableName(); got != "" {
		t.Errorf("templates must not resolve to an executable, got %q", got)
	}
}

func TestTargetExecutableName_Binary(t *testing.T) {
	spec := &BinarySpec{Name: "nuclei", Bin: "nuclei"}
	if got := spec.TargetExecutableName(); got == "" {
		t.Error("a binary spec must resolve to an executable name")
	}
}

func TestBinSpecs_TemplatesPinned(t *testing.T) {
	var found bool
	for _, spec := range binSpecs {
		if spec.Name != "nuclei-templates" {
			continue
		}
		found = true
		if spec.Kind != "templates" {
			t.Errorf("kind = %q, want templates", spec.Kind)
		}
		if spec.Repo != "projectdiscovery/nuclei-templates" {
			t.Errorf("repo = %q", spec.Repo)
		}
		if spec.Version != "v10.4.0" {
			t.Errorf("version = %q, want v10.4.0", spec.Version)
		}
	}
	if !found {
		t.Fatal("nuclei-templates spec is missing")
	}
}
