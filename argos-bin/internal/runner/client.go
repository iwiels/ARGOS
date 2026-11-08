package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ExitSuccess    = 0
	ExitError      = 1
	ExitFindings   = 2
	ExitIncomplete = 3
	ExitCancelled  = 130
	pageSize       = 200
	maxResponse    = 32 << 20
	maxGateRecords = 100000
)

type Client struct {
	baseURL  *url.URL
	http     *http.Client
	username string
	password string
}

type RunInfo struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	StartedAt    int64  `json:"startedAt"`
	UpdatedAt    int64  `json:"updatedAt"`
	EndedAt      *int64 `json:"endedAt,omitempty"`
	LastEventSeq *int64 `json:"lastEventSeq,omitempty"`
	ResumeCount  int    `json:"resumeCount"`
	Error        string `json:"error,omitempty"`
}

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	CaseID   string `json:"caseID"`
}

type FindingCase struct {
	ID                string `json:"id"`
	Status            string `json:"status"`
	AcceptedRiskUntil *int64 `json:"acceptedRiskUntil"`
}

type GateResult struct {
	Failed           bool   `json:"failed"`
	Threshold        string `json:"threshold"`
	MatchingFindings int    `json:"matchingFindings"`
}

type CoverageObservation struct {
	ID           string `json:"id"`
	Surface      string `json:"surface"`
	Role         string `json:"role"`
	TestKey      string `json:"testKey"`
	Status       string `json:"status"`
	FindingCount int    `json:"findingCount"`
	Attestation  string `json:"attestation"`
	RuntimeTool  string `json:"runtimeTool"`
	EvidenceHash string `json:"evidenceHash"`
	EvidenceRef  string `json:"evidenceRef"`
	CreatedAt    int64  `json:"createdAt"`
}

type CoverageRequirement struct {
	Surface     string `json:"surface"`
	Role        string `json:"role"`
	TestKey     string `json:"testKey"`
	RuntimeTool string `json:"runtimeTool"`
}

type CoveragePlan struct {
	SessionID    string                `json:"sessionID"`
	RunID        string                `json:"runID"`
	Version      int                   `json:"version"`
	Source       string                `json:"source"`
	Requirements []CoverageRequirement `json:"requirements"`
	CreatedAt    int64                 `json:"createdAt"`
}

type RunOptions struct {
	SessionID    string
	Prompt       string
	FailOn       string
	PollInterval time.Duration
	Timeout      time.Duration
}

type RunResult struct {
	SessionID            string `json:"sessionID"`
	RunID                string `json:"runID,omitempty"`
	Status               string `json:"status"`
	CoverageStatus       string `json:"coverageStatus"`
	CoverageObservations int    `json:"coverageObservations"`
	CoverageError        string `json:"coverageError,omitempty"`
	StopError            string `json:"stopError,omitempty"`
	GateResult
	ExitCode int `json:"exitCode"`
}

type reportResponse struct {
	Format        string `json:"format"`
	Filename      string `json:"filename"`
	MimeType      string `json:"mimeType"`
	ContentBase64 string `json:"contentBase64"`
	SHA256        string `json:"sha256"`
}

func NewClient(serverURL, username, password string) (*Client, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("server URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("server URL must not contain credentials, a query, or a fragment")
	}
	if password != "" && parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("server credentials require HTTPS unless the server is on localhost")
	}
	if password != "" && username == "" {
		username = "opencode"
	}
	return &Client{
		baseURL:  parsed,
		http:     &http.Client{Timeout: 30 * time.Second},
		username: username,
		password: password,
	}, nil
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, input, output any) error {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawPath = ""
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.password != "" {
		request.SetBasicAuth(c.username, c.password)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponse+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(responseBody) > maxResponse {
		return fmt.Errorf("server response exceeded %d bytes", maxResponse)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(responseBody))
		if len(message) > 1024 {
			message = message[:1024]
		}
		return fmt.Errorf("server returned HTTP %d: %s", response.StatusCode, message)
	}
	if output == nil || len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, output); err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}
	return nil
}

func (c *Client) ListRuns(ctx context.Context, sessionID string) ([]RunInfo, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	var response struct {
		Data []RunInfo `json:"data"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/session/"+url.PathEscape(sessionID)+"/runs", nil, nil, &response); err != nil {
		return nil, err
	}
	sort.Slice(response.Data, func(i, j int) bool {
		if response.Data[i].StartedAt == response.Data[j].StartedAt {
			return response.Data[i].ID > response.Data[j].ID
		}
		return response.Data[i].StartedAt > response.Data[j].StartedAt
	})
	return response.Data, nil
}

func (c *Client) ListCoverage(ctx context.Context, sessionID, runID string) ([]CoverageObservation, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(runID) == "" || len(runID) > 200 {
		return nil, errors.New("run ID must contain between 1 and 200 characters")
	}
	var response struct {
		Data *[]CoverageObservation `json:"data"`
	}
	path := "/api/session/" + url.PathEscape(sessionID) + "/runs/" + url.PathEscape(runID) + "/coverage"
	if err := c.request(ctx, http.MethodGet, path, nil, nil, &response); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, errors.New("coverage response did not include a data array")
	}
	for _, observation := range *response.Data {
		if observation.ID == "" || observation.FindingCount < 0 {
			return nil, errors.New("coverage response contains an invalid observation")
		}
		if observation.Attestation != "api-reported" && observation.Attestation != "runtime-observed" {
			return nil, fmt.Errorf("coverage response contains unknown attestation %q", observation.Attestation)
		}
		if observation.Attestation == "runtime-observed" && (!isSHA256Hex(observation.EvidenceHash) ||
			strings.TrimSpace(observation.EvidenceRef) == "" || len(observation.EvidenceRef) > 2048) {
			return nil, errors.New("runtime coverage response is missing a valid evidence hash or reference")
		}
		switch observation.Status {
		case "executed", "no-finding", "blocked", "skipped", "inconclusive":
		default:
			return nil, fmt.Errorf("coverage response contains unknown status %q", observation.Status)
		}
		if observation.Status == "no-finding" && observation.FindingCount != 0 {
			return nil, errors.New("coverage response marks a finding as no-finding")
		}
		if observation.Status == "executed" && observation.FindingCount < 1 {
			return nil, errors.New("coverage response marks executed coverage without findings")
		}
	}
	return *response.Data, nil
}

func (c *Client) GetCoveragePlan(ctx context.Context, sessionID, runID string) (*CoveragePlan, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(runID) == "" || len(runID) > 200 {
		return nil, errors.New("run ID must contain between 1 and 200 characters")
	}
	var response struct {
		Data json.RawMessage `json:"data"`
	}
	path := "/api/session/" + url.PathEscape(sessionID) + "/runs/" + url.PathEscape(runID) + "/coverage-plan"
	if err := c.request(ctx, http.MethodGet, path, nil, nil, &response); err != nil {
		return nil, err
	}
	data := bytes.TrimSpace(response.Data)
	if len(data) == 0 {
		return nil, errors.New("coverage plan response did not include data")
	}
	if bytes.Equal(data, []byte("null")) {
		return nil, nil
	}
	var plan CoveragePlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("decode coverage plan: %w", err)
	}
	if plan.SessionID != sessionID || plan.RunID != runID {
		return nil, errors.New("coverage plan does not belong to the requested session and run")
	}
	if plan.Version != 1 || plan.Source != "controller" || plan.CreatedAt <= 0 || len(plan.Requirements) == 0 || len(plan.Requirements) > 256 {
		return nil, errors.New("coverage plan has an unsupported version, source, or requirement count")
	}
	seen := make(map[string]struct{}, len(plan.Requirements))
	for _, requirement := range plan.Requirements {
		if !validCoverageSurface(requirement.Surface) || strings.TrimSpace(requirement.Role) == "" || len(requirement.Role) > 120 ||
			requirement.Role != strings.TrimSpace(requirement.Role) || strings.TrimSpace(requirement.TestKey) == "" ||
			len(requirement.TestKey) > 200 || requirement.TestKey != strings.TrimSpace(requirement.TestKey) ||
			strings.TrimSpace(requirement.RuntimeTool) == "" || len(requirement.RuntimeTool) > 160 ||
			requirement.RuntimeTool != strings.TrimSpace(requirement.RuntimeTool) {
			return nil, errors.New("coverage plan contains an invalid requirement")
		}
		key := coverageRequirementKey(requirement)
		if _, exists := seen[key]; exists {
			return nil, errors.New("coverage plan contains duplicate requirements")
		}
		seen[key] = struct{}{}
	}
	return &plan, nil
}

func (c *Client) Run(ctx context.Context, options RunOptions) (RunResult, error) {
	result := RunResult{SessionID: options.SessionID, Status: "incomplete", ExitCode: ExitIncomplete}
	if err := validateSessionID(options.SessionID); err != nil {
		return result, err
	}
	if strings.TrimSpace(options.Prompt) == "" {
		return result, errors.New("prompt must not be empty")
	}
	if _, ok := severityRank(options.FailOn); !ok {
		return result, fmt.Errorf("unsupported --fail-on severity %q", options.FailOn)
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 2 * time.Second
	}
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	before, err := c.ListRuns(runCtx, options.SessionID)
	if err != nil {
		if runCtx.Err() != nil {
			return contextEndedResult(result, ctx), nil
		}
		return result, err
	}
	beforeIDs := make(map[string]struct{}, len(before))
	var active *RunInfo
	if len(before) > 0 && before[0].Status == "interrupted" {
		result.Status = "interrupted"
		return result, nil
	}
	for i := range before {
		beforeIDs[before[i].ID] = struct{}{}
		if before[i].Status == "running" && active == nil {
			active = &before[i]
		}
	}

	messageID, err := newMessageID()
	if err != nil {
		return result, fmt.Errorf("create prompt identity: %w", err)
	}
	var admitted struct {
		Data struct {
			ID          string `json:"id"`
			SessionID   string `json:"sessionID"`
			AdmittedSeq *int64 `json:"admittedSeq"`
		} `json:"data"`
	}
	payload := map[string]any{
		"id":       messageID,
		"prompt":   map[string]string{"text": options.Prompt},
		"delivery": "queue",
	}
	if err := c.request(runCtx, http.MethodPost, "/api/session/"+url.PathEscape(options.SessionID)+"/prompt", nil, payload, &admitted); err != nil {
		if runCtx.Err() != nil {
			return c.stopRun(result, ctx), nil
		}
		return result, err
	}
	if admitted.Data.ID != messageID || admitted.Data.SessionID != options.SessionID || admitted.Data.AdmittedSeq == nil {
		return result, errors.New("server prompt admission did not match the requested message and session")
	}
	var targetID string
	if active != nil {
		targetID = active.ID
	}
	for {
		runs, err := c.ListRuns(runCtx, options.SessionID)
		if err != nil {
			if context.Cause(runCtx) != nil {
				return c.stopRun(result, ctx), nil
			}
			return result, err
		}
		for _, run := range runs {
			if _, existed := beforeIDs[run.ID]; !existed && (targetID == "" || run.StartedAt >= findStartedAt(runs, targetID)) {
				targetID = run.ID
			}
		}
		if targetID != "" {
			current := findRun(runs, targetID)
			if current != nil && current.Status != "running" && current.LastEventSeq != nil && *current.LastEventSeq >= *admitted.Data.AdmittedSeq {
				if current.Status != "completed" {
					result.RunID = current.ID
					result.Status = current.Status
					return result, nil
				}
				result.RunID = current.ID
				result.Status = current.Status
				gate, err := c.evaluateSession(runCtx, options.SessionID, options.FailOn)
				if err != nil {
					if runCtx.Err() != nil {
						return contextEndedResult(result, ctx), nil
					}
					return result, err
				}
				result.GateResult = gate
				coverage, err := c.ListCoverage(runCtx, options.SessionID, current.ID)
				if err != nil {
					if runCtx.Err() != nil {
						return contextEndedResult(result, ctx), nil
					}
					result.CoverageStatus = "unavailable"
					result.CoverageError = err.Error()
				} else {
					result.CoverageObservations = len(coverage)
					plan, planErr := c.GetCoveragePlan(runCtx, options.SessionID, current.ID)
					if planErr != nil {
						if runCtx.Err() != nil {
							return contextEndedResult(result, ctx), nil
						}
						result.CoverageStatus = "unavailable"
						result.CoverageError = planErr.Error()
					} else {
						result.CoverageStatus = coverageStatus(coverage, plan)
					}
				}
				result.ExitCode = ExitIncomplete
				if gate.Failed {
					result.ExitCode = ExitFindings
				} else if result.CoverageStatus == "plan-complete" {
					result.ExitCode = ExitSuccess
				}
				return result, nil
			}
		}
		if err := wait(runCtx, options.PollInterval); err != nil {
			return c.stopRun(result, ctx), nil
		}
	}
}

func coverageStatus(observations []CoverageObservation, plan *CoveragePlan) string {
	if plan == nil {
		if len(observations) == 0 {
			return "not-recorded"
		}
		for _, observation := range observations {
			if observation.Attestation == "runtime-observed" &&
				(observation.Status == "blocked" || observation.Status == "skipped" || observation.Status == "inconclusive") {
				return "runtime-incomplete"
			}
		}
		for _, observation := range observations {
			if observation.Attestation != "runtime-observed" {
				return "reported-unverified"
			}
		}
		return "runtime-unplanned"
	}
	latest := make(map[string]CoverageObservation, len(plan.Requirements))
	for _, observation := range observations {
		if observation.Attestation != "runtime-observed" {
			continue
		}
		key := coverageRequirementKey(CoverageRequirement{
			Surface: observation.Surface,
			Role:    observation.Role,
			TestKey: observation.TestKey,
		})
		previous, ok := latest[key]
		if !ok || observation.CreatedAt >= previous.CreatedAt {
			latest[key] = observation
		}
	}
	for _, requirement := range plan.Requirements {
		observation, ok := latest[coverageRequirementKey(requirement)]
		if !ok {
			return "plan-incomplete"
		}
		if observation.RuntimeTool != requirement.RuntimeTool || !isSHA256Hex(observation.EvidenceHash) ||
			strings.TrimSpace(observation.EvidenceRef) == "" || len(observation.EvidenceRef) > 2048 {
			return "plan-incomplete"
		}
		switch observation.Status {
		case "no-finding":
			if observation.FindingCount != 0 {
				return "plan-incomplete"
			}
		case "executed":
			if observation.FindingCount < 1 {
				return "plan-incomplete"
			}
		case "blocked", "skipped", "inconclusive":
			return "runtime-incomplete"
		default:
			return "plan-incomplete"
		}
	}
	return "plan-complete"
}

func coverageRequirementKey(requirement CoverageRequirement) string {
	return requirement.Surface + "\x00" + requirement.Role + "\x00" + requirement.TestKey
}

func validCoverageSurface(surface string) bool {
	switch surface {
	case "web", "api", "repository":
		return true
	default:
		return false
	}
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func (c *Client) stopRun(result RunResult, parentCtx context.Context) RunResult {
	result = contextEndedResult(result, parentCtx)
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Cancel(stopCtx, result.SessionID); err != nil {
		result.StopError = err.Error()
	}
	return result
}

func contextEndedResult(result RunResult, parentCtx context.Context) RunResult {
	if parentCtx.Err() != nil {
		result.Status = "cancelled"
		result.ExitCode = ExitCancelled
	} else {
		result.Status = "incomplete"
		result.ExitCode = ExitIncomplete
	}
	return result
}

func (c *Client) Status(ctx context.Context, sessionID string) ([]RunInfo, error) {
	return c.ListRuns(ctx, sessionID)
}

func (c *Client) Cancel(ctx context.Context, sessionID string) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	return c.request(ctx, http.MethodPost, "/session/"+url.PathEscape(sessionID)+"/abort", nil, nil, nil)
}

func (c *Client) Export(ctx context.Context, sessionID, format, outputPath string) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}
	if !supportedFormat(format) {
		return fmt.Errorf("unsupported export format %q", format)
	}
	if strings.TrimSpace(outputPath) == "" {
		return errors.New("output path must not be empty")
	}
	var response reportResponse
	payload := map[string]string{"format": format}
	if err := c.request(ctx, http.MethodPost, "/session/"+url.PathEscape(sessionID)+"/report/export", nil, payload, &response); err != nil {
		return err
	}
	if !strings.EqualFold(response.Format, format) {
		return fmt.Errorf("report format mismatch: requested %s, server returned %s", format, response.Format)
	}
	content, err := base64.StdEncoding.DecodeString(response.ContentBase64)
	if err != nil {
		return fmt.Errorf("decode report artifact: %w", err)
	}
	actualHash := sha256.Sum256(content)
	if !strings.EqualFold(hex.EncodeToString(actualHash[:]), response.SHA256) {
		return fmt.Errorf("report artifact SHA-256 mismatch: server returned %s, calculated %s", response.SHA256, hex.EncodeToString(actualHash[:]))
	}
	absolute, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(absolute), ".argos-report-*")
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("protect report permissions: %w", err)
	}
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return fmt.Errorf("write report: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync report: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	if err := os.Rename(tempName, absolute); err != nil {
		return fmt.Errorf("publish verified report: %w", err)
	}
	return nil
}

func (c *Client) evaluateSession(ctx context.Context, sessionID, threshold string) (GateResult, error) {
	findings, err := c.listFindings(ctx, sessionID)
	if err != nil {
		return GateResult{}, err
	}
	cases, err := c.listFindingCases(ctx, sessionID)
	if err != nil {
		return GateResult{}, err
	}
	return EvaluateGate(findings, cases, threshold, time.Now()), nil
}

func (c *Client) listFindings(ctx context.Context, sessionID string) ([]Finding, error) {
	var result []Finding
	total := -1
	for offset := 0; ; {
		query := url.Values{"limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(offset)}}
		var response struct {
			Data  []Finding `json:"data"`
			Total int       `json:"total"`
		}
		if err := c.request(ctx, http.MethodGet, "/api/session/"+url.PathEscape(sessionID)+"/findings", query, nil, &response); err != nil {
			return nil, err
		}
		if err := validatePage(offset, len(response.Data), response.Total, &total); err != nil {
			return nil, fmt.Errorf("incomplete finding evaluation: %w", err)
		}
		result = append(result, response.Data...)
		if offset+len(response.Data) >= total {
			return result, nil
		}
		offset += len(response.Data)
	}
}

func (c *Client) listFindingCases(ctx context.Context, sessionID string) ([]FindingCase, error) {
	var result []FindingCase
	total := -1
	for offset := 0; ; {
		query := url.Values{"limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(offset)}}
		var response struct {
			Data  []FindingCase `json:"data"`
			Total int           `json:"total"`
		}
		if err := c.request(ctx, http.MethodGet, "/api/session/"+url.PathEscape(sessionID)+"/finding-cases", query, nil, &response); err != nil {
			return nil, err
		}
		if err := validatePage(offset, len(response.Data), response.Total, &total); err != nil {
			return nil, fmt.Errorf("incomplete finding case evaluation: %w", err)
		}
		result = append(result, response.Data...)
		if offset+len(response.Data) >= total {
			return result, nil
		}
		offset += len(response.Data)
	}
}

func validatePage(offset, count, reportedTotal int, expectedTotal *int) error {
	if reportedTotal < 0 || reportedTotal > maxGateRecords {
		return fmt.Errorf("reported record count %d is outside the supported range", reportedTotal)
	}
	if *expectedTotal == -1 {
		*expectedTotal = reportedTotal
	} else if reportedTotal != *expectedTotal {
		return fmt.Errorf("record count changed during pagination from %d to %d", *expectedTotal, reportedTotal)
	}
	if offset+count > reportedTotal {
		return fmt.Errorf("page contains %d records beyond the reported total %d", offset+count, reportedTotal)
	}
	if count == 0 && offset < reportedTotal {
		return fmt.Errorf("page at offset %d is empty before the reported total %d", offset, reportedTotal)
	}
	return nil
}

func EvaluateGate(findings []Finding, cases []FindingCase, threshold string, now time.Time) GateResult {
	thresholdRank, ok := severityRank(threshold)
	if !ok {
		return GateResult{Failed: true, Threshold: strings.ToLower(threshold)}
	}
	caseByID := make(map[string]FindingCase, len(cases))
	for _, findingCase := range cases {
		caseByID[findingCase.ID] = findingCase
	}
	result := GateResult{Threshold: strings.ToLower(threshold)}
	for _, finding := range findings {
		if finding.CaseID != "" {
			if findingCase, exists := caseByID[finding.CaseID]; exists {
				switch findingCase.Status {
				case "remediated":
					continue
				case "accepted-risk":
					if findingCase.AcceptedRiskUntil != nil && *findingCase.AcceptedRiskUntil > now.UnixMilli() {
						continue
					}
				}
			}
		} else if finding.Status == "remediated" {
			continue
		}
		rank, _ := severityRank(finding.Severity)
		if rank >= thresholdRank {
			result.MatchingFindings++
		}
	}
	result.Failed = result.MatchingFindings > 0
	return result
}

func severityRank(value string) (int, bool) {
	rank, ok := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[strings.ToLower(strings.TrimSpace(value))]
	return rank, ok
}

func validateSessionID(sessionID string) error {
	if !strings.HasPrefix(sessionID, "ses_") || len(sessionID) < 5 {
		return errors.New("session ID must use the Argos ses_ identifier")
	}
	for _, char := range sessionID[4:] {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-') {
			return errors.New("session ID contains unsupported characters")
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newMessageID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "msg_" + hex.EncodeToString(value), nil
}

func supportedFormat(format string) bool {
	switch format {
	case "pdf", "sarif", "defectdojo", "junit", "html", "sbom", "har", "csv", "markdown":
		return true
	default:
		return false
	}
}

func findRun(runs []RunInfo, id string) *RunInfo {
	for i := range runs {
		if runs[i].ID == id {
			return &runs[i]
		}
	}
	return nil
}

func findStartedAt(runs []RunInfo, id string) int64 {
	if run := findRun(runs, id); run != nil {
		return run.StartedAt
	}
	return 0
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
