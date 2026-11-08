type Requester = (path: string, init?: RequestInit) => Promise<Response>

export type ProjectWebhookConfig = {
  url: string
  secret?: string
  format?: "generic" | "jira" | "slack"
  enabled: boolean
}

export type WebhookTestResult = {
  ok: boolean
  statusCode: number
  responseBody?: string
}

/** Persists (or, with `null`, clears) a project's webhook config. Returns false if the server doesn't support it yet. */
export async function updateProjectWebhook(
  request: Requester,
  projectID: string,
  webhook: ProjectWebhookConfig | null,
): Promise<boolean> {
  const response = await request(`/project/${encodeURIComponent(projectID)}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ webhook }),
  })
  if (response.status === 404 || response.status === 405) return false
  if (!response.ok) throw new Error(`Unable to update project webhook (HTTP ${response.status})`)
  return true
}

/** Sends a synthetic test finding to the given webhook URL without saving. Returns undefined if the server doesn't support it yet. */
export async function testProjectWebhook(
  request: Requester,
  projectID: string,
  config: { url: string; secret?: string; format?: "generic" | "jira" | "slack" },
): Promise<WebhookTestResult | undefined> {
  const response = await request(`/project/${encodeURIComponent(projectID)}/webhook/test`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(config),
  })
  if (response.status === 404 || response.status === 405) return undefined
  if (!response.ok) throw new Error(`Unable to test project webhook (HTTP ${response.status})`)
  const body = await response.json()
  if (!body || typeof body !== "object") return undefined
  const record = body as Record<string, unknown>
  return {
    ok: record.ok === true,
    statusCode: typeof record.statusCode === "number" ? record.statusCode : 0,
    responseBody: typeof record.responseBody === "string" ? record.responseBody : undefined,
  }
}

export type { Requester }
