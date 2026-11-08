import { Effect } from "effect"
import type { FindingTable } from "./sql"

type FindingRow = typeof FindingTable.$inferSelect

export interface WebhookDispatchOptions {
  url: string
  secret?: string
  format?: "generic" | "jira" | "slack"
  headers?: Record<string, string>
  timeoutMs?: number
  jiraProjectKey?: string
}

export interface WebhookDispatchResult {
  ok: boolean
  statusCode: number
  responseBody?: string
  dispatchedCount: number
}

/**
 * Despacha hallazgos a un webhook saliente (Genérico, Jira REST API o Slack/Teams).
 */
export function dispatchFindingsWebhook(
  findings: FindingRow[],
  opts: WebhookDispatchOptions,
): Effect.Effect<WebhookDispatchResult> {
  return Effect.tryPromise({
    try: async () => {
      const timeoutMs = opts.timeoutMs ?? 10000
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)

      let payload: unknown
      if (opts.format === "jira") {
        // Formato para creación / actualización en Jira Service Management / Software
        payload = {
          issues: findings.map((f) => ({
            fields: {
              project: { key: opts.jiraProjectKey ?? "SEC" },
              summary: `[Argos][${f.severity.toUpperCase()}] ${f.title}`,
              description: `*Target:* ${f.target ?? "N/A"}\n*Vector:* ${f.vector ?? "N/A"}\n*CWE:* ${f.cwe ?? "N/A"}\n*Severidad:* ${f.severity}\n\n*Evidencia:*\n${typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence, null, 2)}\n\n*Remediación recomendada:*\n${f.remediation ?? "N/A"}`,
              issuetype: { name: "Bug" },
              priority: { name: f.severity === "critical" ? "Highest" : f.severity === "high" ? "High" : "Medium" },
              labels: ["argos-security", f.severity, ...(f.tags ?? [])],
            },
          })),
        }
      } else if (opts.format === "slack") {
        payload = {
          text: `🚨 *Argos Security Alert* — ${findings.length} hallazgo(s) detectado(s)`,
          blocks: [
            {
              type: "section",
              text: {
                type: "mrkdwn",
                text: `*Argos Security Engine* ha reportado *${findings.length}* hallazgo(s):`,
              },
            },
            ...findings.slice(0, 5).map((f) => ({
              type: "section",
              text: {
                type: "mrkdwn",
                text: `• *[${f.severity.toUpperCase()}]* ${f.title}\n> *Vector:* \`${f.vector ?? f.target ?? "N/A"}\``,
              },
            })),
          ],
        }
      } else {
        payload = {
          event: "argos.findings.dispatched",
          timestamp: Date.now(),
          count: findings.length,
          findings: findings.map((f) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            status: f.status,
            target: f.target,
            vector: f.vector,
            cwe: f.cwe,
            remediation: f.remediation,
            enrichment: f.enrichment,
            timeCreated: f.time_created,
          })),
        }
      }

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "User-Agent": "Argos-Webhook-Dispatcher/1.0",
        ...(opts.headers ?? {}),
      }

      if (opts.secret) {
        headers["X-Argos-Secret"] = opts.secret
      }

      try {
        const response = await fetch(opts.url, {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
          signal: controller.signal,
        })
        const text = await response.text()
        return {
          ok: response.ok,
          statusCode: response.status,
          responseBody: text.slice(0, 500),
          dispatchedCount: findings.length,
        }
      } finally {
        clearTimeout(timer)
      }
    },
    catch: (error: unknown) => error,
  }).pipe(
    Effect.catch((error) =>
      Effect.succeed({
        ok: false,
        statusCode: 0,
        responseBody: error instanceof Error ? error.message : String(error),
        dispatchedCount: findings.length,
      }),
    ),
  )
}
