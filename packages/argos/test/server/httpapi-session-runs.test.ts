import { expect } from "bun:test"
import { NodeHttpServer } from "@effect/platform-node"
import { SessionV2 } from "@argos/core/session"
import { SessionCoverage } from "@argos/core/session/coverage"
import { RunConflictError } from "@argos/core/session/error"
import { SessionGroup } from "@argos/server/groups/session"
import { SessionHandler } from "@argos/server/handlers/session"
import { Authorization as ServerAuthorization } from "@argos/server/middleware/authorization"
import { schemaErrorLayer } from "@argos/server/middleware/schema-error"
import { SessionLocationMiddleware } from "@argos/server/middleware/session-location"
import { Effect, Layer } from "effect"
import { HttpClient, HttpClientRequest, HttpRouter } from "effect/unstable/http"
import { HttpApi, HttpApiBuilder } from "effect/unstable/httpapi"
import { testEffect } from "../lib/effect"

const sessionID = SessionV2.ID.make("ses_httpapi_runs")
const runID = "run_coverage_test"
const api = HttpApi.make("server").add(SessionGroup)
let coverageReportInput: unknown
const coverageRow: SessionCoverage.Info = {
  id: "coverage_httpapi_test",
  sessionID,
  runID,
  surface: "web",
  role: "anonymous",
  testKey: "http-headers",
  status: "no-finding",
  findingCount: 0,
  attestation: "api-reported",
  createdAt: 1,
}
const coveragePlan: SessionCoverage.PlanInfo = {
  sessionID,
  runID,
  version: 1,
  source: "controller",
  requirements: [{ surface: "web", role: "anonymous", testKey: "http-headers", runtimeTool: "argos-web.headers" }],
  createdAt: 1,
}
const server = HttpRouter.serve(
  HttpApiBuilder.layer(api).pipe(
    Layer.provide(SessionHandler),
    Layer.provide([
      schemaErrorLayer,
      Layer.succeed(
        ServerAuthorization,
        ServerAuthorization.of((effect) => effect),
      ),
      Layer.succeed(
        SessionLocationMiddleware,
        SessionLocationMiddleware.of((effect) =>
          effect as Effect.Effect<Effect.Success<typeof effect>, Effect.Error<typeof effect>>,
        ),
      ),
      Layer.mock(SessionV2.Service)({
        runs: () =>
          Effect.succeed([
            {
              id: "run_interrupted",
              status: "interrupted",
              startedAt: 1,
              updatedAt: 2,
              endedAt: 2,
              lastEventSeq: 8,
              resumeCount: 0,
              error: "Execution interrupted",
            },
          ]),
        resumeInterrupted: (id, runID) => {
          if (runID !== "run_interrupted") {
            return Effect.fail(new RunConflictError({ sessionID: id, runID, reason: "not_interrupted" }))
          }
          return Effect.sync(() => {
            expect(id).toBe(sessionID)
            expect(runID).toBe("run_interrupted")
          })
        },
        coverage: (input) => {
          expect(input).toEqual({ sessionID, runID })
          return Effect.succeed([coverageRow])
        },
        coveragePlan: (input) => {
          expect(input.sessionID).toBe(sessionID)
          if (input.runID === "run_without_plan") return Effect.succeed(undefined)
          expect(input.runID).toBe(runID)
          return Effect.succeed(coveragePlan)
        },
        reportCoverage: (input) => {
          coverageReportInput = input
          return Effect.succeed(coverageRow)
        },
      }),
    ]),
  ),
  { disableListenLog: true, disableLogger: true },
).pipe(Layer.provideMerge(NodeHttpServer.layerTest))

const it = testEffect(server)

it.effect("lists coverage attached to the exact session execution", () =>
  Effect.gen(function* () {
    const response = yield* HttpClientRequest.get(`/api/session/${sessionID}/runs/${runID}/coverage`).pipe(
      HttpClient.execute,
    )

    expect(response.status).toBe(200)
    expect(yield* response.json).toEqual({ data: [coverageRow] })
  }),
)

it.effect("returns only the immutable controller plan for the exact execution", () =>
  Effect.gen(function* () {
    const response = yield* HttpClientRequest.get(`/api/session/${sessionID}/runs/${runID}/coverage-plan`).pipe(
      HttpClient.execute,
    )

    expect(response.status).toBe(200)
    expect(yield* response.json).toEqual({ data: coveragePlan })
  }),
)

it.effect("returns null when the controller has not generated a plan", () =>
  Effect.gen(function* () {
    const response = yield* HttpClientRequest.get(`/api/session/${sessionID}/runs/run_without_plan/coverage-plan`).pipe(
      HttpClient.execute,
    )

    expect(response.status).toBe(200)
    expect(yield* response.json).toEqual({ data: null })
  }),
)

it.effect("records coverage from the route identity and discards client attestation fields", () =>
  Effect.gen(function* () {
    const response = yield* HttpClientRequest.post(`/api/session/${sessionID}/runs/${runID}/coverage`).pipe(
      HttpClientRequest.bodyJson({
        surface: "api",
        role: "member",
        testKey: "object-read",
        status: "blocked",
        attestation: "runtime-observed",
        runtimeTool: "forged-tool-name",
      }),
      Effect.flatMap(HttpClient.execute),
    )

    expect(response.status).toBe(200)
    expect(coverageReportInput).toEqual({
      sessionID,
      runID,
      surface: "api",
      role: "member",
      testKey: "object-read",
      status: "blocked",
    })
  }),
)

it.effect("lists interrupted executions and exposes explicit resume", () =>
  Effect.gen(function* () {
    const runs = yield* HttpClientRequest.get(`/api/session/${sessionID}/runs`).pipe(HttpClient.execute)
    expect(runs.status).toBe(200)
    expect(yield* runs.json).toEqual({
      data: [
        {
          id: "run_interrupted",
          status: "interrupted",
          startedAt: 1,
          updatedAt: 2,
          endedAt: 2,
          lastEventSeq: 8,
          resumeCount: 0,
          error: "Execution interrupted",
        },
      ],
    })

    const resumed = yield* HttpClientRequest.post(`/api/session/${sessionID}/resume`).pipe(
      HttpClientRequest.bodyJson({ runID: "run_interrupted" }),
      Effect.flatMap(HttpClient.execute),
    )
    expect(resumed.status).toBe(204)

    const conflict = yield* HttpClientRequest.post(`/api/session/${sessionID}/resume`).pipe(
      HttpClientRequest.bodyJson({ runID: "run_completed" }),
      Effect.flatMap(HttpClient.execute),
    )
    if (conflict.status !== 409)
      return yield* Effect.die(`Unexpected resume conflict response: ${yield* conflict.text}`)
    expect(conflict.status).toBe(409)
  }),
)
