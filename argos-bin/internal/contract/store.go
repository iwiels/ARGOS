package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Record is the shape a finding takes on disk in the shared memory store
// (<memoryDir>/findings/*.json).
//
// It is the canonical contract (Finding) plus the metadata the backend needs
// to reconcile it back into a session: `kind` (the reconciler discards
// anything that is not a finding), `argos_session_id` (the exact Session ID
// of Argos — the store is shared between campaigns, so this field is the only
// thing that says which session a finding belongs to) and `session` (a
// human-readable campaign label).
type Record struct {
	Kind  string `json:"kind"`
	Agent string `json:"agent"`
	// Session is the campaign label: readable, NOT unique.
	Session string `json:"session"`
	// ArgosSessionID is the exact Session ID of Argos Desktop (ses_...).
	ArgosSessionID  string   `json:"argos_session_id,omitempty"`
	ID              string   `json:"id,omitempty"`
	Source          string   `json:"source,omitempty"`
	Title           string   `json:"title"`
	Target          string   `json:"target,omitempty"`
	Severity        string   `json:"severity,omitempty"`
	Status          string   `json:"status,omitempty"`
	Confidence      string   `json:"confidence,omitempty"`
	AgentAssessment string   `json:"agent_assessment,omitempty"`
	Impact          string   `json:"impact,omitempty"`
	CWE             string   `json:"cwe,omitempty"`
	RuleID          string   `json:"rule_id,omitempty"`
	OWASP           []string `json:"owasp,omitempty"`
	// Evidence is either the tool's evidence object or the plain text an
	// agent transcribed; the backend normalizes both.
	Evidence    any         `json:"evidence,omitempty"`
	Vector      string      `json:"vector,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
	CVSS        *CVSSVector `json:"cvss,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	References  []string    `json:"references,omitempty"`

	NeedsFollowupBy []string `json:"needs_followup_by,omitempty"`
	SourceTool      string   `json:"source_tool,omitempty"`
	Timestamp       string   `json:"timestamp"`
}

// DefaultStatus is the initial status of a scanner candidate.
const DefaultStatus = "observed"


// WriteRecord writes a record into dir and returns the path of the file.
//
// The file name is unique per finding: the timestamp orders the store and a
// content hash tells two findings apart even when they land in the same
// second. The backend does NOT rely on the name — it deduplicates by
// taxonomy (CWE + target + vector) — but a stable name keeps the store
// readable and idempotent.
func WriteRecord(dir string, rec Record) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("missing memory dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("cannot create findings directory: %w", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot encode finding: %w", err)
	}
	path := filepath.Join(dir, recordFilename(rec, data))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("cannot write finding: %w", err)
	}
	return path, nil
}

// recordFilename builds the file name of a record: <campaign>-<timestamp>-<hash>.json
func recordFilename(rec Record, data []byte) string {
	slug := slugify(rec.Session)
	if slug == "" {
		slug = "argos"
	}
	ts := rec.Timestamp
	if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
		ts = parsed.UTC().Format("20060102-150405")
	} else {
		ts = time.Now().UTC().Format("20060102-150405")
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%s-%s-%s.json", slug, ts, hex.EncodeToString(sum[:])[:12])
}

// slugify reduces a campaign label to something safe for a file name.
func slugify(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
