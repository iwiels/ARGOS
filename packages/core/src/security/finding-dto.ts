import { normalizeActor, normalizeVerdict, type FeedbackRow } from "./finding-feedback"
import { FindingTable } from "./sql"

export function toSecurityFeedbackDTO(row: FeedbackRow) {
  return {
    findingID: row.finding_id,
    verdict: normalizeVerdict(row.verdict) ?? "accepted-risk",
    reason: row.reason ?? null,
    actor: normalizeActor(row.actor),
    ruleID: row.rule_id ?? null,
    sourceTool: row.source_tool ?? null,
    cwe: row.cwe ?? null,
    createdAt: row.time_created,
    updatedAt: row.time_updated,
  }
}

export function toSecurityFindingDTO(row: typeof FindingTable.$inferSelect, feedback?: FeedbackRow) {
  return {
    id: row.id,
    sessionID: row.session_id,
    projectID: row.project_id,
    caseID: row.case_id ?? null,
    fingerprint: row.fingerprint,
    title: row.title,
    severity: row.severity,
    status: row.status,
    source: row.source,
    sourceTool: row.source_tool ?? null,
    agent: row.agent ?? null,
    target: row.target ?? null,
    cwe: row.cwe ?? null,
    vector: row.vector ?? null,
    evidence: row.evidence,
    remediation: row.remediation ?? null,
    tags: row.tags,
    attackTechniques: row.attack_techniques ?? undefined,
    iocs: row.iocs ?? undefined,
    enrichedAt: row.enriched_at ?? undefined,
    feedback: feedback
      ? {
          verdict: normalizeVerdict(feedback.verdict) ?? "accepted-risk",
          reason: feedback.reason ?? null,
          actor: normalizeActor(feedback.actor),
        }
      : undefined,
    createdAt: row.time_created,
    updatedAt: row.time_updated,
  }
}
