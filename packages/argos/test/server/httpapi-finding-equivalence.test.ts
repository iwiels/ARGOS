import { expect } from "bun:test"
import { NodeHttpServer } from "@effect/platform-node"
import { Audit } from "@argos/core/audit"
import { Database } from "@argos/core/database/database"
import { FindingTable } from "@argos/core/security/sql"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { SecurityGroup } from "@argos/server/groups/security"
import { SecurityHandler } from "@argos/server/handlers/security"
import { SessionLocationMiddleware } from "@argos/server/middleware/session-location"
import { schemaErrorLayer as serverSchemaErrorLayer } from "@argos/server/middleware/schema-error"
import { Authorization as ServerAuthorization } from "@argos/server/middleware/authorization"
import { Effect, Layer } from "effect"
import { HttpClient, HttpClientRequest, HttpRouter } from "effect/unstable/http"
import { HttpApi, HttpApiBuilder } from "effect/unstable/httpapi"
import { Session } from "../../src/session/session"
import { FindingApi } from "../../src/server/routes/instance/httpapi/groups/finding"
import { findingHandlers } from "../../src/server/routes/instance/httpapi/handlers/finding"
import { Authorization } from "../../src/server/routes/instance/httpapi/middleware/authorization"
import { schemaErrorLayer } from "../../src/server/routes/instance/httpapi/middleware/schema-error"
import { InstanceContextMiddleware } from "../../src/server/routes/instance/httpapi/middleware/instance-context"
import { WorkspaceRouteContext, WorkspaceRoutingMiddleware } from "../../src/server/routes/instance/httpapi/middleware/workspace-routing"
import { testEffect } from "../lib/effect"

const legacyApi = HttpApi.make("opencode-instance").addHttpApi(FindingApi)
const api = HttpApi.make("server").add(SecurityGroup)
const database = Database.layerFromPath(":memory:")
const server = HttpRouter.serve(Layer.mergeAll(HttpApiBuilder.layer(legacyApi), HttpApiBuilder.layer(api)).pipe(
  Layer.provide([findingHandlers, SecurityHandler]),
  Layer.provide([
    schemaErrorLayer,
    serverSchemaErrorLayer,
    Layer.succeed(ServerAuthorization, ServerAuthorization.of((effect) => effect)),
    Layer.succeed(Authorization, Authorization.of((effect) => effect)),
    Layer.succeed(InstanceContextMiddleware, InstanceContextMiddleware.of((effect) => effect)),
    Layer.succeed(WorkspaceRoutingMiddleware, WorkspaceRoutingMiddleware.of((effect) => effect.pipe(
      Effect.provideService(WorkspaceRouteContext, { directory: "/project" }),
    ))),
    Layer.succeed(SessionLocationMiddleware, SessionLocationMiddleware.of((effect) =>
      effect as Effect.Effect<Effect.Success<typeof effect>, Effect.Error<typeof effect>>,
    )),
    Layer.mock(Session.Service)({}),
  ]),
  Layer.provide(Audit.defaultLayer),
  Layer.provide(database),
), { disableListenLog: true, disableLogger: true }).pipe(
  Layer.provideMerge(NodeHttpServer.layerTest),
)
const it = testEffect(Layer.mergeAll(database, server))

it.effect("finding routes share persisted DTOs and feedback while preserving their response contracts", () => Effect.gen(function* () {
  const session = { id: SessionV2.ID.make("ses_equivalence"), projectID: Project.ID.global }
  const other = { id: SessionV2.ID.make("ses_equivalence_other"), projectID: Project.ID.global }
  const { db } = yield* Database.Service
  yield* db.insert(ProjectTable).values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] }).run().pipe(Effect.orDie)
  for (const item of [session, other]) {
    yield* db.insert(SessionTable).values({ id: item.id, project_id: item.projectID, slug: item.id, directory: "/project", title: "equivalence", version: "test" }).run().pipe(Effect.orDie)
  }
  for (const [id, owner, severity, updated] of [
    ["fnd_equivalent_a", session, "high", 30],
    ["fnd_equivalent_b", session, "low", 20],
    ["fnd_equivalent_other", other, "high", 40],
  ] as const) {
    yield* db.insert(FindingTable).values({
      id, session_id: owner.id, project_id: owner.projectID, fingerprint: id, title: id,
      severity, status: "open", source: "agent-reviewed", source_tool: "web.scan", evidence: { status: 200 },
      tags: ["web"], raw: "preserved raw", time_created: 1, time_updated: updated,
    }).run().pipe(Effect.orDie)
  }
  const request = (path: string, payload?: { verdict: string; reason?: string }) => Effect.gen(function* () {
    const request = HttpClientRequest.make(payload ? "POST" : "GET")(path)
    const response = yield* HttpClient.execute(payload ? HttpClientRequest.bodyJsonUnsafe(request, payload) : request)
    const body = (yield* response.json) as Record<string, any>
    expect(response.status, `${path}: ${JSON.stringify(body)}`).toBe(200)
    return body
  })
  const legacyPath = `/session/${session.id}/findings`
  const apiPath = `/api/session/${session.id}/findings`
  const legacy = yield* request(legacyPath)
  const api = yield* request(apiPath)
  expect(Object.keys(legacy).sort()).toEqual(["findings", "total"])
  expect(Object.keys(api).sort()).toEqual(["data", "limit", "offset", "total"])
  expect(legacy.total).toBe(2)
  expect(api.total).toBe(2)
  expect(api.limit).toBe(50)
  expect(api.offset).toBe(0)
  expect(api.data.map((item: Record<string, unknown>, index: number) => {
    const legacyItem = legacy.findings[index]
    expect(legacyItem.session_id).toBe(item.sessionID)
    expect(legacyItem.project_id).toBe(item.projectID)
    expect(legacyItem.source_tool).toBe(item.sourceTool)
    expect(legacyItem.raw).toBe("preserved raw")
    return Object.fromEntries(Object.keys(item).map((key) => [key, legacyItem[key] ?? null]))
  })).toEqual(api.data)
  const page = yield* request(`${legacyPath}?limit=1&offset=1`)
  const apiPage = yield* request(`${apiPath}?limit=1&offset=1`)
  expect(page.total).toBe(apiPage.total)
  expect(page.findings.map((item: { id: string }) => item.id)).toEqual(apiPage.data.map((item: { id: string }) => item.id))
  yield* request(`${legacyPath}/fnd_equivalent_a/feedback`, { verdict: "false-positive", reason: "Reviewed in legacy" })
  const suppressed = yield* request(legacyPath)
  expect(suppressed.total).toBe(2)
  expect(suppressed.findings[0].feedback).toEqual({ verdict: "false-positive", reason: "Reviewed in legacy", actor: "human" })
  const suppressedDetail = yield* request(`${apiPath}/fnd_equivalent_a`)
  expect(suppressedDetail.data.feedback).toEqual(suppressed.findings[0].feedback)
  const visible = yield* request(apiPath)
  expect(visible.total).toBe(1)
  expect(visible.data[0].id).toBe("fnd_equivalent_b")
  const includingSuppressed = yield* request(`${apiPath}?includeSuppressed=true`)
  expect(includingSuppressed.total).toBe(2)
  expect(includingSuppressed.data.find((item: { id: string }) => item.id === "fnd_equivalent_a").feedback).toEqual({
    verdict: "false-positive",
    reason: "Reviewed in legacy",
    actor: "human",
  })
  const suppressedPage = yield* request(`${apiPath}?includeSuppressed=false`)
  expect(suppressedPage.total).toBe(1)
  expect(suppressedPage.data[0].id).toBe("fnd_equivalent_b")
  yield* request(`${apiPath}/fnd_equivalent_a/feedback`, { verdict: "true-positive", reason: "Confirmed through API" })
  const updated = yield* request(legacyPath)
  expect(updated.findings[0].feedback).toEqual({ verdict: "true-positive", reason: "Confirmed through API", actor: "human" })
  const detail = yield* request(`${apiPath}/fnd_equivalent_a`)
  expect(detail.data.feedback).toEqual(updated.findings[0].feedback)
  const filtered = yield* request(`${apiPath}?severity=low&status=open`)
  expect(filtered.total).toBe(1)
  expect(filtered.data[0].id).toBe("fnd_equivalent_b")
  expect((yield* request(`${legacyPath}?limit=0`)).findings).toEqual([])
}), 30_000)
