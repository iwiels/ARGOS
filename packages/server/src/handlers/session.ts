import { SessionV2 } from "@argos/core/session"
import { DateTime, Effect } from "effect"
import { HttpApiBuilder, HttpApiSchema } from "effect/unstable/httpapi"
import { Api } from "../api"
import { SessionsCursor } from "../groups/session"
import {
  ConflictError,
  InvalidRequestError,
  InvalidCursorError,
  ServiceUnavailableError,
  SessionNotFoundError,
  SessionRunNotFoundError,
  UnknownError,
} from "../errors"

const DefaultSessionsLimit = 50

export const SessionHandler = HttpApiBuilder.group(Api, "server.session", (handlers) =>
  Effect.gen(function* () {
    const session = yield* SessionV2.Service

    return handlers
      .handle(
        "session.list",
        Effect.fn(function* (ctx) {
          const query =
            ctx.query.cursor !== undefined
              ? yield* SessionsCursor.parse(ctx.query.cursor).pipe(
                  Effect.mapError(() => new InvalidCursorError({ message: "Invalid cursor" })),
                )
              : ctx.query
          const sessions = yield* session.list({
            ...query,
            workspaceID: query.workspace,
            limit: ctx.query.limit ?? DefaultSessionsLimit,
          })
          const first = sessions[0]
          const last = sessions.at(-1)
          return {
            data: sessions,
            cursor: {
              previous: first
                ? SessionsCursor.make({
                    ...query,
                    anchor: {
                      id: first.id,
                      time: DateTime.toEpochMillis(first.time.created),
                      direction: "previous",
                    },
                  })
                : undefined,
              next: last
                ? SessionsCursor.make({
                    ...query,
                    anchor: {
                      id: last.id,
                      time: DateTime.toEpochMillis(last.time.created),
                      direction: "next",
                    },
                  })
                : undefined,
            },
          }
        }),
      )
      .handle(
        "session.prompt",
        Effect.fn(function* (ctx) {
          return {
            data: yield* session
              .prompt({
                sessionID: ctx.params.sessionID,
                id: ctx.payload.id,
                prompt: ctx.payload.prompt,
                delivery: ctx.payload.delivery,
                resume: ctx.payload.resume,
              })
              .pipe(
                Effect.catchTag("Session.NotFoundError", (error) =>
                  Effect.fail(
                    new SessionNotFoundError({
                      sessionID: error.sessionID,
                      message: `Session not found: ${error.sessionID}`,
                    }),
                  ),
                ),
                Effect.catchTag("Session.PromptConflictError", (error) =>
                  Effect.fail(
                    new ConflictError({
                      message: `Prompt message ID conflicts with an existing durable record: ${error.messageID}`,
                      resource: error.messageID,
                    }),
                  ),
                ),
              ),
          }
        }),
      )
      .handle(
        "session.runs",
        Effect.fn(function* (ctx) {
          return {
            data: yield* session.runs(ctx.params.sessionID).pipe(
              Effect.catchTag("Session.NotFoundError", (error) =>
                Effect.fail(
                  new SessionNotFoundError({
                    sessionID: error.sessionID,
                    message: `Session not found: ${error.sessionID}`,
                  }),
                ),
              ),
            ),
          }
        }),
      )
      .handle(
        "session.coverage",
        Effect.fn(function* (ctx) {
          return {
            data: yield* session.coverage(ctx.params).pipe(
              Effect.catchTag("Session.NotFoundError", (error) =>
                Effect.fail(
                  new SessionNotFoundError({
                    sessionID: error.sessionID,
                    message: `Session not found: ${error.sessionID}`,
                  }),
                ),
              ),
              Effect.catchTag("Session.CoverageRunNotFoundError", (error) =>
                Effect.fail(
                  new SessionRunNotFoundError({
                    sessionID: error.sessionID,
                    runID: error.runID,
                    message: `Execution ${error.runID} was not found for session ${error.sessionID}.`,
                  }),
                ),
              ),
            ),
          }
        }),
      )
      .handle(
        "session.coverage-plan",
        Effect.fn(function* (ctx) {
          const plan = yield* session.coveragePlan(ctx.params).pipe(
            Effect.catchTag("Session.NotFoundError", (error) =>
              Effect.fail(
                new SessionNotFoundError({
                  sessionID: error.sessionID,
                  message: `Session not found: ${error.sessionID}`,
                }),
              ),
            ),
            Effect.catchTag("Session.CoverageRunNotFoundError", (error) =>
              Effect.fail(
                new SessionRunNotFoundError({
                  sessionID: error.sessionID,
                  runID: error.runID,
                  message: `Execution ${error.runID} was not found for session ${error.sessionID}.`,
                }),
              ),
            ),
          )
          return { data: plan ?? null }
        }),
      )
      .handle(
        "session.coverage.report",
        Effect.fn(function* (ctx) {
          const data = yield* session.reportCoverage({ ...ctx.params, ...ctx.payload }).pipe(
            Effect.catch(
              (
                error,
              ): Effect.Effect<
                never,
                ConflictError | InvalidRequestError | SessionNotFoundError | SessionRunNotFoundError
              > => {
                switch (error._tag) {
                  case "Session.NotFoundError":
                    return Effect.fail(
                      new SessionNotFoundError({
                        sessionID: error.sessionID,
                        message: `Session not found: ${error.sessionID}`,
                      }),
                    )
                  case "Session.CoverageRunNotFoundError":
                    return Effect.fail(
                      new SessionRunNotFoundError({
                        sessionID: error.sessionID,
                        runID: error.runID,
                        message: `Execution ${error.runID} was not found for session ${error.sessionID}.`,
                      }),
                    )
                  case "Session.CoverageIdempotencyConflictError":
                    return Effect.fail(
                      new ConflictError({
                        resource: error.runID,
                        message: `Coverage idempotency key ${error.key} was reused with different content.`,
                      }),
                    )
                  case "Session.CoverageValidationError":
                    return Effect.fail(new InvalidRequestError({ message: error.message, kind: "coverage" }))
                }
              },
            ),
          )
          return { data }
        }),
      )
      .handle(
        "session.resume",
        Effect.fn(function* (ctx) {
          yield* session.resumeInterrupted(ctx.params.sessionID, ctx.payload.runID).pipe(
            Effect.catch((error): Effect.Effect<never, ConflictError | SessionNotFoundError | UnknownError> => {
              if (error._tag === "Session.NotFoundError") {
                return Effect.fail(
                  new SessionNotFoundError({
                    sessionID: error.sessionID,
                    message: `Session not found: ${error.sessionID}`,
                  }),
                )
              }
              if (error._tag === "Session.RunConflictError") {
                return Effect.fail(
                  new ConflictError({
                    resource: error.runID,
                    message: `Execution ${error.runID} cannot be resumed (${error.reason}).`,
                  }),
                )
              }
              return Effect.fail(new UnknownError({ message: "Session resume failed" }))
            }),
          )
          return HttpApiSchema.NoContent.make()
        }),
      )
      .handle(
        "session.compact",
        Effect.fn(function* (ctx) {
          yield* session.compact({ sessionID: ctx.params.sessionID }).pipe(
            Effect.catchTag("Session.NotFoundError", (error) =>
              Effect.fail(
                new SessionNotFoundError({
                  sessionID: error.sessionID,
                  message: `Session not found: ${error.sessionID}`,
                }),
              ),
            ),
            Effect.catchTag("Session.OperationUnavailableError", (error) =>
              Effect.fail(
                new ServiceUnavailableError({
                  message: `Session ${error.operation} is not available yet`,
                  service: `session.${error.operation}`,
                }),
              ),
            ),
          )
          return HttpApiSchema.NoContent.make()
        }),
      )
      .handle(
        "session.wait",
        Effect.fn(function* (ctx) {
          yield* session.wait(ctx.params.sessionID).pipe(
            Effect.catchTag("Session.NotFoundError", (error) =>
              Effect.fail(
                new SessionNotFoundError({
                  sessionID: error.sessionID,
                  message: `Session not found: ${error.sessionID}`,
                }),
              ),
            ),
            Effect.catchTag("Session.OperationUnavailableError", (error) =>
              Effect.fail(
                new ServiceUnavailableError({
                  message: `Session ${error.operation} is not available yet`,
                  service: `session.${error.operation}`,
                }),
              ),
            ),
          )
          return HttpApiSchema.NoContent.make()
        }),
      )
      .handle(
        "session.context",
        Effect.fn(function* (ctx) {
          return {
            data: yield* session.context(ctx.params.sessionID).pipe(
              Effect.catchTag("Session.NotFoundError", (error) =>
                Effect.fail(
                  new SessionNotFoundError({
                    sessionID: error.sessionID,
                    message: `Session not found: ${error.sessionID}`,
                  }),
                ),
              ),
              Effect.catchTag("Session.MessageDecodeError", (error) => {
                const ref = `err_${crypto.randomUUID().slice(0, 8)}`
                return Effect.logError("failed to decode session message").pipe(
                  Effect.annotateLogs({ ref, sessionID: error.sessionID, messageID: error.messageID }),
                  Effect.andThen(
                    Effect.fail(
                      new UnknownError({
                        message: "Unexpected server error. Check server logs for details.",
                        ref,
                      }),
                    ),
                  ),
                )
              }),
            ),
          }
        }),
      )
  }),
)
