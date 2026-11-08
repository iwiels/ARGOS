package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ARG-053 — el contrato canónico tiene un solo golden file, compartido con el
// backend TypeScript (`packages/core/test/fixtures/finding-contract.json`).
//
// El test de TS compara su lista runtime de campos, sus vocabularios y sus
// límites contra ese archivo; este compara el struct Go con `reflect`. Un
// campo que se agregue de un solo lado rompe uno de los dos tests, que es
// exactamente lo que el contrato necesita: que la desincronización sea ruidosa.

const goldenRelativePath = "../../../packages/core/test/fixtures/finding-contract.json"

type goldenField struct {
	JSON     string `json:"json"`
	TS       string `json:"ts"`
	Go       string `json:"go"`
	Required bool   `json:"required"`
}

type goldenFile struct {
	Version     int            `json:"version"`
	Severities  []string       `json:"severities"`
	Confidences []string       `json:"confidences"`
	Fields      []goldenField  `json:"fields"`
	Limits      map[string]int `json:"limits"`
	Sample      map[string]any `json:"sample"`
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(goldenRelativePath))
	if err != nil {
		t.Fatalf("no se pudo leer el golden file del contrato: %v", err)
	}
	var file goldenFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("golden file inválido: %v", err)
	}
	if file.Version != 1 {
		t.Fatalf("versión del golden inesperada: %d", file.Version)
	}
	return file
}

func TestFindingWireFieldsMatchGolden(t *testing.T) {
	file := loadGolden(t)

	type wire struct {
		json     string
		goName   string
		required bool
	}
	var actual []wire
	typ := reflect.TypeOf(Finding{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		required := true
		for _, opt := range parts[1:] {
			if opt == "omitempty" {
				required = false
			}
		}
		actual = append(actual, wire{json: parts[0], goName: field.Name, required: required})
	}

	var expected []wire
	for _, field := range file.Fields {
		if field.Go == "" {
			// Campo que solo existe en TS (p. ej. `poc`, que las tools Go
			// escriben dentro de `evidence`).
			continue
		}
		expected = append(expected, wire{json: field.JSON, goName: field.Go, required: field.Required})
	}

	if len(actual) != len(expected) {
		t.Fatalf("el struct Finding tiene %d campos wire y el golden declara %d", len(actual), len(expected))
	}
	for i := range actual {
		if actual[i] != expected[i] {
			t.Fatalf("campo %d: el struct dice %+v y el golden dice %+v", i, actual[i], expected[i])
		}
	}
}

func TestFindingVocabulariesMatchGolden(t *testing.T) {
	file := loadGolden(t)

	severities := []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	if !reflect.DeepEqual(severities, file.Severities) {
		t.Fatalf("severidades Go %v != golden %v", severities, file.Severities)
	}
	confidences := []string{ConfidenceConfirmed, ConfidenceProbable, ConfidencePossible}
	if !reflect.DeepEqual(confidences, file.Confidences) {
		t.Fatalf("confianzas Go %v != golden %v", confidences, file.Confidences)
	}
}

func TestFindingSampleRoundTrips(t *testing.T) {
	file := loadGolden(t)

	raw, err := json.Marshal(file.Sample)
	if err != nil {
		t.Fatalf("no se pudo serializar el sample: %v", err)
	}
	var finding Finding
	if err := json.Unmarshal(raw, &finding); err != nil {
		t.Fatalf("el sample no decodifica al struct Finding: %v", err)
	}

	// Todo campo declarado como requerido tiene que sobrevivir el round-trip.
	required := map[string]bool{}
	for _, field := range file.Fields {
		if field.Go != "" && field.Required {
			required[field.Go] = true
		}
	}
	value := reflect.ValueOf(finding)
	for i := 0; i < value.NumField(); i++ {
		name := value.Type().Field(i).Name
		if !required[name] {
			continue
		}
		if value.Field(i).IsZero() {
			t.Fatalf("el campo requerido %s quedó vacío tras decodificar el sample", name)
		}
	}

	// Y el hallazgo normalizado mantiene la forma canónica al re-serializarse.
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("no se pudo re-serializar el finding: %v", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("el finding re-serializado no es JSON válido: %v", err)
	}
	for _, field := range file.Fields {
		if field.Go == "" {
			continue
		}
		if _, ok := roundTripped[field.JSON]; !ok && field.Required {
			t.Fatalf("el campo requerido %q desapareció al re-serializar", field.JSON)
		}
	}
}
