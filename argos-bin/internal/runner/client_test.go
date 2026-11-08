package runner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClientRejectsCredentialsOverPublicHTTP(t *testing.T) {
	for _, serverURL := range []string{"http://198.51.100.24:4096", "http://192.168.1.10:4096"} {
		_, err := NewClient(serverURL, "opencode", "secret")
		if err == nil || !strings.Contains(err.Error(), "HTTPS") {
			t.Fatalf("expected credentials to require HTTPS off localhost for %s, got %v", serverURL, err)
		}
	}
}

func TestRunWaitsForActiveExecutionAndAppliesFindingGate(t *testing.T) {
	runsCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
			runsCalls++
			status := "running"
			run := map[string]any{"id": "run_active", "status": status, "startedAt": 20, "lastEventSeq": 1}
			if runsCalls == 2 {
				run["status"] = "completed"
				delete(run, "lastEventSeq")
			}
			if runsCalls > 2 {
				run["status"] = "completed"
				run["lastEventSeq"] = 5
			}
			json.NewEncoder(w).Encode(map[string]any{"data": []any{
				run,
				map[string]any{"id": "run_old", "status": "interrupted", "startedAt": 10, "lastEventSeq": 2},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode prompt: %v", err)
			}
			prompt, ok := body["prompt"].(map[string]any)
			if !ok || prompt["text"] != "audit target" {
				t.Errorf("unexpected prompt payload: %#v", body)
			}
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": body["id"], "sessionID": "ses_test", "admittedSeq": 5}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/findings":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "finding-1", "severity": "high", "caseID": "case-open"}}, "total": 1})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/finding-cases":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "case-open", "status": "open"}}, "total": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Run(context.Background(), RunOptions{
		SessionID:    "ses_test",
		Prompt:       "audit target",
		FailOn:       "high",
		PollInterval: time.Millisecond,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != "run_active" || result.Status != "completed" || result.ExitCode != ExitFindings {
		t.Fatalf("unexpected run result: %+v", result)
	}
	if runsCalls < 3 {
		t.Fatalf("run with no event cursor must not complete the request: got %d reads", runsCalls)
	}
}

func TestExportRejectsHashMismatchWithoutWritingOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/session/ses_test/report/export" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"format":        "sarif",
			"filename":      "report.sarif",
			"mimeType":      "application/json",
			"contentBase64": base64.StdEncoding.EncodeToString([]byte("{}")),
			"sha256":        strings.Repeat("0", 64),
			"contentHash":   strings.Repeat("0", 64),
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "report.sarif")
	err = client.Export(context.Background(), "ses_test", "sarif", output)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected hash mismatch error, got %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("output must not exist after failed verification, stat error: %v", err)
	}
}

func TestCancelUsesSessionAbortEndpoint(t *testing.T) {
	cancelled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/session/ses_test/abort" {
			cancelled = true
			json.NewEncoder(w).Encode(true)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Cancel(context.Background(), "ses_test"); err != nil {
		t.Fatal(err)
	}
	if !cancelled {
		t.Fatal("cancel must call the session-specific abort endpoint")
	}
}

func TestRunDoesNotSubmitPromptWhenLatestExecutionIsInterrupted(t *testing.T) {
	promptRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs" {
			json.NewEncoder(w).Encode(map[string]any{"data": []any{
				map[string]any{"id": "run_interrupted", "status": "interrupted", "startedAt": 20, "lastEventSeq": 5},
			}})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt" {
			promptRequests++
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Run(context.Background(), RunOptions{
		SessionID: "ses_test",
		Prompt:    "audit target",
		FailOn:    "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "interrupted" || result.ExitCode != ExitIncomplete || promptRequests != 0 {
		t.Fatalf("interrupted run must require explicit recovery: result=%+v prompts=%d", result, promptRequests)
	}
}

func TestExportWritesArtifactAfterHashVerification(t *testing.T) {
	content := []byte("{\"version\":\"2.1.0\"}")
	digest := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/session/ses_test/report/export" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"format":        "sarif",
			"filename":      "report.sarif",
			"mimeType":      "application/json",
			"contentBase64": base64.StdEncoding.EncodeToString(content),
			"sha256":        hex.EncodeToString(digest[:]),
			"contentHash":   hex.EncodeToString(digest[:]),
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "nested", "report.sarif")
	if err := client.Export(context.Background(), "ses_test", "sarif", output); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(content) {
		t.Fatalf("unexpected report contents: %q", written)
	}
}

func TestExportRejectsArtifactInAnotherFormat(t *testing.T) {
	content := []byte("%PDF-1.7")
	digest := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/session/ses_test/report/export" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"format":        "pdf",
			"filename":      "report.pdf",
			"mimeType":      "application/pdf",
			"contentBase64": base64.StdEncoding.EncodeToString(content),
			"sha256":        hex.EncodeToString(digest[:]),
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "report.sarif")
	err = client.Export(context.Background(), "ses_test", "sarif", output)
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("expected report format mismatch error, got %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("output must not exist after format mismatch, stat error: %v", err)
	}
}

func TestRunDoesNotPassGateWhenFindingPageIsIncomplete(t *testing.T) {
	runsCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
			runsCalls++
			status := "running"
			lastEventSeq := 1
			if runsCalls > 1 {
				status = "completed"
				lastEventSeq = 5
			}
			json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
				"id": "run_new", "status": status, "startedAt": 10, "lastEventSeq": lastEventSeq,
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode prompt: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"id": body["id"], "sessionID": "ses_test", "admittedSeq": 5,
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/findings":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 1, "limit": 200, "offset": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/finding-cases":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0, "limit": 200, "offset": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs/run_new/coverage":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs/run_new/coverage-plan":
			json.NewEncoder(w).Encode(map[string]any{"data": nil})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Run(context.Background(), RunOptions{
		SessionID:    "ses_test",
		Prompt:       "audit target",
		FailOn:       "high",
		PollInterval: time.Millisecond,
		Timeout:      time.Second,
	})
	if err == nil || result.ExitCode == ExitSuccess {
		t.Fatalf("incomplete finding pagination must fail closed: result=%+v error=%v", result, err)
	}
}

func TestRunReportsCoverageAttestationAndStillFailsClosed(t *testing.T) {
	cases := []struct {
		name        string
		attestation string
		status      string
		plan        any
		observation any
		want        string
		wantExit    int
	}{
		{name: "api claim", attestation: "api-reported", status: "no-finding", want: "reported-unverified", wantExit: ExitIncomplete},
		{name: "runtime no-finding without a plan", attestation: "runtime-observed", status: "no-finding", want: "runtime-unplanned", wantExit: ExitIncomplete},
		{name: "runtime blocked", attestation: "runtime-observed", status: "blocked", want: "runtime-incomplete", wantExit: ExitIncomplete},
		{
			name:        "all required runtime evidence complete",
			attestation: "runtime-observed",
			status:      "no-finding",
			plan: map[string]any{
				"sessionID": "ses_test", "runID": "run_new", "version": 1, "source": "controller",
				"requirements": []any{map[string]any{
					"surface": "web", "role": "anonymous", "testKey": "tls-protocols", "runtimeTool": "argos-web.tls",
				}},
				"createdAt": 1,
			},
			observation: map[string]any{
				"surface": "web", "role": "anonymous", "testKey": "tls-protocols", "runtimeTool": "argos-web.tls",
			},
			want: "plan-complete", wantExit: ExitSuccess,
		},
		{
			name:        "runtime evidence for a different planned check",
			attestation: "runtime-observed",
			status:      "no-finding",
			plan: map[string]any{
				"sessionID": "ses_test", "runID": "run_new", "version": 1, "source": "controller",
				"requirements": []any{map[string]any{
					"surface": "api", "role": "member", "testKey": "object-authorization", "runtimeTool": "argos-web.api",
				}},
				"createdAt": 1,
			},
			observation: map[string]any{
				"surface": "web", "role": "anonymous", "testKey": "tls-protocols", "runtimeTool": "argos-web.tls",
			},
			want: "plan-incomplete", wantExit: ExitIncomplete,
		},
		{
			name:        "runtime evidence from a different tool",
			attestation: "runtime-observed",
			status:      "no-finding",
			plan: map[string]any{
				"sessionID": "ses_test", "runID": "run_new", "version": 1, "source": "controller",
				"requirements": []any{map[string]any{
					"surface": "web", "role": "anonymous", "testKey": "tls-protocols", "runtimeTool": "argos-web.tls",
				}},
				"createdAt": 1,
			},
			observation: map[string]any{
				"surface": "web", "role": "anonymous", "testKey": "tls-protocols", "runtimeTool": "argos-web.headers",
			},
			want: "plan-incomplete", wantExit: ExitIncomplete,
		},
		{
			name:        "plan for another run is rejected",
			attestation: "runtime-observed",
			status:      "no-finding",
			plan: map[string]any{
				"sessionID": "ses_test", "runID": "run_other", "version": 1, "source": "controller",
				"requirements": []any{map[string]any{
					"surface": "web", "role": "anonymous", "testKey": "tls-protocols", "runtimeTool": "argos-web.tls",
				}},
				"createdAt": 1,
			},
			observation: map[string]any{
				"surface": "web", "role": "anonymous", "testKey": "tls-protocols", "runtimeTool": "argos-web.tls",
			},
			want: "unavailable", wantExit: ExitIncomplete,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runsCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
					runsCalls++
					status := "running"
					lastEventSeq := 1
					if runsCalls > 1 {
						status = "completed"
						lastEventSeq = 5
					}
					json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
						"id": "run_new", "status": status, "startedAt": 10, "lastEventSeq": lastEventSeq,
					}}})
				case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("decode prompt: %v", err)
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"id": body["id"], "sessionID": "ses_test", "admittedSeq": 5,
					}})
				case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/findings":
					json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0, "limit": 200, "offset": 0})
				case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/finding-cases":
					json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0, "limit": 200, "offset": 0})
				case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs/run_new/coverage":
					observation, ok := test.observation.(map[string]any)
					if !ok {
						observation = map[string]any{}
					}
					observation["id"] = "coverage-1"
					observation["attestation"] = test.attestation
					observation["status"] = test.status
					observation["findingCount"] = 0
					observation["createdAt"] = 1
					if test.attestation == "runtime-observed" {
						observation["evidenceHash"] = strings.Repeat("a", 64)
						observation["evidenceRef"] = "argos://evidence/run/coverage.json"
					}
					json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
						"id": observation["id"], "attestation": observation["attestation"], "status": observation["status"], "findingCount": observation["findingCount"],
						"surface": observation["surface"], "role": observation["role"], "testKey": observation["testKey"],
						"runtimeTool": observation["runtimeTool"], "createdAt": observation["createdAt"],
						"evidenceHash": observation["evidenceHash"], "evidenceRef": observation["evidenceRef"],
					}}})
				case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs/run_new/coverage-plan":
					json.NewEncoder(w).Encode(map[string]any{"data": test.plan})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client, err := NewClient(server.URL, "", "")
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Run(context.Background(), RunOptions{
				SessionID:    "ses_test",
				Prompt:       "audit target",
				FailOn:       "high",
				PollInterval: time.Millisecond,
				Timeout:      time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.CoverageStatus != test.want || result.CoverageObservations != 1 || result.ExitCode != test.wantExit {
				t.Fatalf("coverage must be reported but must not produce a clean gate: %+v", result)
			}
		})
	}
}

func TestCoverageStatusUsesLatestRuntimeObservationForEveryRequirement(t *testing.T) {
	plan := &CoveragePlan{
		Requirements: []CoverageRequirement{
			{Surface: "web", Role: "anonymous", TestKey: "headers", RuntimeTool: "argos-web.headers"},
			{Surface: "api", Role: "member", TestKey: "object-authorization", RuntimeTool: "argos-web.api"},
		},
	}
	completeHeaders := CoverageObservation{
		Surface: "web", Role: "anonymous", TestKey: "headers", RuntimeTool: "argos-web.headers",
		Status: "no-finding", Attestation: "runtime-observed", EvidenceHash: strings.Repeat("a", 64),
		EvidenceRef: "argos://evidence/run/headers.json", CreatedAt: 1,
	}
	completeAPI := CoverageObservation{
		Surface: "api", Role: "member", TestKey: "object-authorization", RuntimeTool: "argos-web.api",
		Status: "executed", FindingCount: 1, Attestation: "runtime-observed", EvidenceHash: strings.Repeat("b", 64),
		EvidenceRef: "argos://evidence/run/object-authorization.json", CreatedAt: 2,
	}

	if status := coverageStatus([]CoverageObservation{completeHeaders, completeAPI}, plan); status != "plan-complete" {
		t.Fatalf("all runtime requirements should complete the plan, got %q", status)
	}
	if status := coverageStatus([]CoverageObservation{completeHeaders}, plan); status != "plan-incomplete" {
		t.Fatalf("missing required evidence must keep the plan incomplete, got %q", status)
	}
	blockedRetry := completeHeaders
	blockedRetry.Status = "blocked"
	blockedRetry.CreatedAt = 3
	if status := coverageStatus([]CoverageObservation{completeHeaders, blockedRetry, completeAPI}, plan); status != "runtime-incomplete" {
		t.Fatalf("a later blocked runtime attempt must invalidate that requirement, got %q", status)
	}
}

func TestListCoverageRejectsRuntimeObservationWithoutEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
			"id": "coverage-1", "surface": "web", "role": "anonymous", "testKey": "headers",
			"status": "no-finding", "findingCount": 0, "attestation": "runtime-observed", "runtimeTool": "argos-web.headers",
		}}})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListCoverage(context.Background(), "ses_test", "run_test"); err == nil || !strings.Contains(err.Error(), "evidence hash or reference") {
		t.Fatalf("runtime evidence without a hash and reference must be rejected, got %v", err)
	}
}

func TestRunMarksMissingCoverageEndpointUnavailable(t *testing.T) {
	runsCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
			runsCalls++
			status := "running"
			lastEventSeq := 1
			if runsCalls > 1 {
				status = "completed"
				lastEventSeq = 5
			}
			json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
				"id": "run_new", "status": status, "startedAt": 10, "lastEventSeq": lastEventSeq,
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode prompt: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"id": body["id"], "sessionID": "ses_test", "admittedSeq": 5,
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/findings":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0, "limit": 200, "offset": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/finding-cases":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0, "limit": 200, "offset": 0})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Run(context.Background(), RunOptions{
		SessionID:    "ses_test",
		Prompt:       "audit target",
		FailOn:       "high",
		PollInterval: time.Millisecond,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CoverageStatus != "unavailable" || result.CoverageError == "" || result.ExitCode != ExitIncomplete {
		t.Fatalf("missing coverage API must stay incomplete and report why: %+v", result)
	}
}

func TestRunDoesNotReturnGreenWithoutPersistedCoverage(t *testing.T) {
	runsCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
			runsCalls++
			status := "running"
			lastEventSeq := 1
			if runsCalls > 1 {
				status = "completed"
				lastEventSeq = 5
			}
			json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
				"id": "run_new", "status": status, "startedAt": 10, "lastEventSeq": lastEventSeq,
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode prompt: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"id": body["id"], "sessionID": "ses_test", "admittedSeq": 5,
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/findings":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0, "limit": 200, "offset": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/finding-cases":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "total": 0, "limit": 200, "offset": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs/run_new/coverage":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs/run_new/coverage-plan":
			json.NewEncoder(w).Encode(map[string]any{"data": nil})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Run(context.Background(), RunOptions{
		SessionID:    "ses_test",
		Prompt:       "audit target",
		FailOn:       "high",
		PollInterval: time.Millisecond,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || result.ExitCode != ExitIncomplete || result.CoverageStatus != "not-recorded" {
		t.Fatalf("a clean result without coverage evidence must remain incomplete: %+v", result)
	}
}

func TestRunRejectsPromptAdmissionForAnotherSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs" {
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt" {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode prompt: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"id": body["id"], "sessionID": "ses_other", "admittedSeq": 5,
			}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Run(context.Background(), RunOptions{
		SessionID:    "ses_test",
		Prompt:       "audit target",
		FailOn:       "high",
		PollInterval: time.Millisecond,
		Timeout:      5 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("expected exact-session admission rejection, got %v", err)
	}
}

func TestRunCancellationDuringPromptSubmissionAbortsSession(t *testing.T) {
	promptStarted := make(chan struct{})
	releasePrompt := make(chan struct{})
	var cancelRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
			close(promptStarted)
			select {
			case <-r.Context().Done():
			case <-releasePrompt:
			}
		case r.Method == http.MethodPost && r.URL.Path == "/session/ses_test/abort":
			cancelRequests.Add(1)
			json.NewEncoder(w).Encode(true)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan struct {
		result RunResult
		err    error
	}, 1)
	go func() {
		result, err := client.Run(ctx, RunOptions{SessionID: "ses_test", Prompt: "audit target", FailOn: "high"})
		resultCh <- struct {
			result RunResult
			err    error
		}{result: result, err: err}
	}()
	<-promptStarted
	cancel()
	close(releasePrompt)
	outcome := <-resultCh
	if outcome.err != nil || outcome.result.ExitCode != ExitCancelled || cancelRequests.Load() != 1 {
		t.Fatalf("cancel during admission must abort and return 130: result=%+v error=%v aborts=%d", outcome.result, outcome.err, cancelRequests.Load())
	}
}

func TestRunReportsFailureToAbortAfterTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
				"id": "run_active", "status": "running", "startedAt": 10, "lastEventSeq": 1,
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode prompt: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"id": body["id"], "sessionID": "ses_test", "admittedSeq": 5,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/session/ses_test/abort":
			http.Error(w, "abort failed", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Run(context.Background(), RunOptions{
		SessionID:    "ses_test",
		Prompt:       "audit target",
		FailOn:       "high",
		PollInterval: time.Millisecond,
		Timeout:      5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != ExitIncomplete || !strings.Contains(result.StopError, "HTTP 500") {
		t.Fatalf("timeout abort failure must be visible in the result: %+v", result)
	}
}

func TestRunTimeoutIncludesPromptSubmission(t *testing.T) {
	releasePrompt := make(chan struct{})
	var abortRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/session/ses_test/runs":
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/ses_test/prompt":
			select {
			case <-r.Context().Done():
			case <-releasePrompt:
			}
		case r.Method == http.MethodPost && r.URL.Path == "/session/ses_test/abort":
			abortRequests.Add(1)
			json.NewEncoder(w).Encode(true)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	client.http = &http.Client{Timeout: 20 * time.Millisecond}
	result, err := client.Run(context.Background(), RunOptions{
		SessionID:    "ses_test",
		Prompt:       "audit target",
		FailOn:       "high",
		PollInterval: time.Millisecond,
		Timeout:      5 * time.Millisecond,
	})
	close(releasePrompt)
	if err != nil || result.ExitCode != ExitIncomplete || abortRequests.Load() != 1 {
		t.Fatalf("run timeout must cover admission and abort the admitted session: result=%+v error=%v aborts=%d", result, err, abortRequests.Load())
	}
}
