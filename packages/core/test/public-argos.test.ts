import fs from "fs/promises"
import path from "path"
import { describe, expect } from "bun:test"
import { Effect, Schema } from "effect"
import { AbsolutePath, Argos, Location, Model, OpenCode, Session, Tool } from "@argos/core/public"
import { Database } from "@argos/core/database/database"
import { tmpdir } from "./fixture/tmpdir"
import { testEffect } from "./lib/effect"

// Persistencia desechable: la suite nunca toca la BD real del desarrollador.
const it = testEffect(Argos.layerWithStorage(Database.layerFromPath(":memory:")))

describe("public native Argos API", () => {
  it.effect("exposes intentional Argos and backward-compatible OpenCode capabilities", () =>
    Effect.gen(function* () {
      const argos = yield* Argos.Service
      const opencode = yield* OpenCode.Service

      expect(Object.keys(argos).sort()).toEqual(["sessions", "tools"])
      expect(Object.keys(opencode).sort()).toEqual(["sessions", "tools"])

      expect(Object.keys(opencode.sessions).sort()).toEqual([
        "context",
        "create",
        "events",
        "get",
        "interrupt",
        "list",
        "message",
        "messages",
        "prompt",
        "switchModel",
      ])
      expect(Session.ID.create()).toStartWith("ses_")
      expect(Session.MessageID.create()).toStartWith("msg_")
      expect(yield* opencode.sessions.list()).toBeArray()
      yield* opencode.tools.register({
        public_tool: Tool.make({
          description: "Public tool",
          input: Schema.Struct({}),
          output: Schema.Struct({ ok: Schema.Boolean }),
          execute: () => Effect.succeed({ ok: true }),
        }),
      })
    }),
  )

  it.effect("switches to an available model and variant", () =>
    Effect.acquireRelease(
      Effect.promise(() => tmpdir()),
      (tmp) => Effect.promise(() => tmp[Symbol.asyncDispose]()),
    ).pipe(
      Effect.flatMap((tmp) =>
        Effect.gen(function* () {
          yield* writeProvider(tmp.path)
          const argos = yield* Argos.Service
          const sessionID = Session.ID.create()
          const model = ref({ variant: "fast" })
          yield* argos.sessions.create({
            id: sessionID,
            location: Location.Ref.make({ directory: AbsolutePath.make(tmp.path) }),
          })

          yield* argos.sessions.switchModel({ sessionID, model })

          expect((yield* argos.sessions.get(sessionID)).model).toEqual(model)
        }),
      ),
    ),
  )

  it.effect("rejects missing and Location-disabled models without changing the Session", () =>
    Effect.acquireRelease(
      Effect.promise(() => Promise.all([tmpdir(), tmpdir()])),
      (dirs) => Effect.promise(() => Promise.all(dirs.map((dir) => dir[Symbol.asyncDispose]())).then(() => undefined)),
    ).pipe(
      Effect.flatMap(([available, disabled]) =>
        Effect.gen(function* () {
          yield* writeProvider(available.path)
          yield* writeProvider(disabled.path, true)
          const argos = yield* Argos.Service
          const availableID = Session.ID.create()
          const disabledID = Session.ID.create()
          yield* argos.sessions.create({
            id: availableID,
            location: Location.Ref.make({ directory: AbsolutePath.make(available.path) }),
          })
          yield* argos.sessions.create({
            id: disabledID,
            location: Location.Ref.make({ directory: AbsolutePath.make(disabled.path) }),
          })

          yield* argos.sessions.switchModel({ sessionID: availableID, model: ref({ variant: "default" }) })
          const disabledError = yield* argos.sessions
            .switchModel({ sessionID: disabledID, model: ref() })
            .pipe(Effect.flip)
          const missingError = yield* argos.sessions
            .switchModel({ sessionID: disabledID, model: ref({ id: "missing" }) })
            .pipe(Effect.flip)

          expect(disabledError).toBeInstanceOf(Session.ModelUnavailableError)
          expect(missingError).toBeInstanceOf(Session.ModelUnavailableError)
          expect((yield* argos.sessions.get(availableID)).model).toEqual(ref({ variant: "default" }))
          expect((yield* argos.sessions.get(disabledID)).model).toBeUndefined()
        }),
      ),
    ),
  )

  it.effect("rejects an unavailable variant without changing the Session", () =>
    Effect.acquireRelease(
      Effect.promise(() => tmpdir()),
      (tmp) => Effect.promise(() => tmp[Symbol.asyncDispose]()),
    ).pipe(
      Effect.flatMap((tmp) =>
        Effect.gen(function* () {
          yield* writeProvider(tmp.path)
          const argos = yield* Argos.Service
          const sessionID = Session.ID.create()
          const selected = ref({ variant: "fast" })
          yield* argos.sessions.create({
            id: sessionID,
            location: Location.Ref.make({ directory: AbsolutePath.make(tmp.path) }),
          })
          yield* argos.sessions.switchModel({ sessionID, model: selected })

          const error = yield* argos.sessions
            .switchModel({ sessionID, model: ref({ variant: "unknown" }) })
            .pipe(Effect.flip)

          expect(error).toBeInstanceOf(Session.VariantUnavailableError)
          expect((yield* argos.sessions.get(sessionID)).model).toEqual(selected)
        }),
      ),
    ),
  )

  it.effect("preserves the typed not-found error for a missing Session", () =>
    Effect.gen(function* () {
      const argos = yield* Argos.Service
      const sessionID = Session.ID.create()
      const error = yield* argos.sessions
        .switchModel({
          sessionID,
          model: Schema.decodeUnknownSync(Model.Ref)({ id: "claude-sonnet-4-5", providerID: "anthropic" }),
        })
        .pipe(Effect.flip)

      expect(error).toBeInstanceOf(Session.NotFoundError)
      if (error instanceof Session.NotFoundError) expect(error.sessionID).toBe(sessionID)
    }),
  )
})

const ref = (input: { id?: string; variant?: string } = {}) =>
  Schema.decodeUnknownSync(Model.Ref)({
    id: input.id ?? "chat",
    providerID: "public-test",
    variant: input.variant,
  })

const writeProvider = (directory: string, disabled = false) =>
  Effect.promise(() =>
    fs.writeFile(
      path.join(directory, "opencode.json"),
      JSON.stringify({
        providers: {
          "public-test": {
            name: "Public test",
            api: { type: "native", settings: {} },
            models: {
              chat: {
                disabled,
                variants: [{ id: "fast" }],
              },
            },
          },
        },
      }),
    ),
  )
