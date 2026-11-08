import path from "path"
import os from "os"
import { and, eq, or, sql } from "drizzle-orm"
import { Database } from "@argos/core/database/database"
import { ProjectDirectoryTable, ProjectTable } from "@argos/core/project/sql"
import { SessionTable } from "@argos/core/session/sql"
import { WorkspaceTable } from "@argos/core/control-plane/workspace.sql"
import * as Log from "@argos/core/util/log"
import { Flag } from "@argos/core/flag/flag"
import { GlobalBus } from "@/bus/global"
import { which } from "@argos/core/util/which"
import { Command } from "@/command"
import { InstanceState } from "@/effect/instance-state"
import { Effect, Layer, Scope, Context, Stream, Types, Schema } from "effect"
import { ChildProcess, ChildProcessSpawner } from "effect/unstable/process"
import { FSUtil } from "@argos/core/fs-util"
import { AppProcess } from "@argos/core/process"
import { ProjectV2 } from "@argos/core/project"
import { ProjectCopy } from "@argos/core/project/copy"
import { CrossSpawnSpawner } from "@argos/core/cross-spawn-spawner"
import { AbsolutePath, NonNegativeInt, optionalOmitUndefined } from "@argos/core/schema"
import { serviceUse } from "@argos/core/effect/service-use"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { EventBridge } from "@/event-bridge"
import { EventV2 } from "@argos/core/event"

const log = Log.create({ service: "project" })

const ProjectVcs = Schema.Literal("git")

const ProjectIcon = Schema.Struct({
  url: optionalOmitUndefined(Schema.String),
  override: optionalOmitUndefined(Schema.String),
  color: optionalOmitUndefined(Schema.String),
})

const ProjectCommands = Schema.Struct({
  start: optionalOmitUndefined(
    Schema.String.annotate({ description: "Startup script to run when creating a new workspace (worktree)" }),
  ),
})

const ProjectWebhookFormat = Schema.Literals(["generic", "jira", "slack"])

const ProjectWebhook = Schema.Struct({
  url: Schema.String,
  secret: optionalOmitUndefined(Schema.String),
  format: optionalOmitUndefined(ProjectWebhookFormat),
  enabled: Schema.Boolean,
})

const ProjectTime = Schema.Struct({
  created: NonNegativeInt,
  updated: NonNegativeInt,
  initialized: optionalOmitUndefined(NonNegativeInt),
})

export const ProjectScope = Schema.Struct({
  domains: optionalOmitUndefined(Schema.Array(Schema.String)),
  excluded: optionalOmitUndefined(Schema.Array(Schema.String)),
  cidrs: optionalOmitUndefined(Schema.Array(Schema.String)),
  maxRPS: optionalOmitUndefined(Schema.Number),
  maxConcurrency: optionalOmitUndefined(Schema.Number),
  customHeader: optionalOmitUndefined(Schema.String),
  safeMode: optionalOmitUndefined(Schema.Boolean),
  modality: optionalOmitUndefined(Schema.Literals(["black-box", "grey-box", "white-box"])),
})
export type ProjectScope = Types.DeepMutable<Schema.Schema.Type<typeof ProjectScope>>

export const Info = Schema.Struct({
  id: ProjectV2.ID,
  worktree: Schema.String,
  vcs: optionalOmitUndefined(ProjectVcs),
  name: optionalOmitUndefined(Schema.String),
  icon: optionalOmitUndefined(ProjectIcon),
  commands: optionalOmitUndefined(ProjectCommands),
  webhook: optionalOmitUndefined(ProjectWebhook),
  scope: optionalOmitUndefined(ProjectScope),
  time: ProjectTime,
  sandboxes: Schema.Array(Schema.String),
}).annotate({ identifier: "Project" })
export type Info = Types.DeepMutable<Schema.Schema.Type<typeof Info>>

export const Event = {
  Updated: EventV2.define({ type: "project.updated", schema: Info.fields }),
}

type Row = typeof ProjectTable.$inferSelect

export function fromRow(row: Row): Info {
  const icon =
    row.icon_url || row.icon_url_override || row.icon_color
      ? {
          url: row.icon_url ?? undefined,
          override: row.icon_url_override ?? undefined,
          color: row.icon_color ?? undefined,
        }
      : undefined
  return {
    id: row.id,
    worktree: row.worktree,
    vcs: row.vcs ? Schema.decodeUnknownSync(ProjectVcs)(row.vcs) : undefined,
    name: row.name ?? undefined,
    icon,
    time: {
      created: row.time_created,
      updated: row.time_updated,
      initialized: row.time_initialized ?? undefined,
    },
    sandboxes: row.sandboxes,
    commands: row.commands ?? undefined,
    webhook: row.webhook ?? undefined,
    scope: (row.scope as ProjectScope) ?? undefined,
  }
}

export const UpdateInput = Schema.Struct({
  projectID: ProjectV2.ID,
  directory: Schema.optional(Schema.String),
  name: Schema.optional(Schema.String),
  icon: Schema.optional(ProjectIcon),
  commands: Schema.optional(ProjectCommands),
  webhook: Schema.optional(Schema.NullOr(ProjectWebhook)),
  scope: Schema.optional(Schema.NullOr(ProjectScope)),
})
export type UpdateInput = Types.DeepMutable<Schema.Schema.Type<typeof UpdateInput>>

export const UpdatePayload = Schema.Struct({
  directory: Schema.optional(Schema.String),
  name: Schema.optional(Schema.String),
  icon: Schema.optional(ProjectIcon),
  commands: Schema.optional(ProjectCommands),
  webhook: Schema.optional(Schema.NullOr(ProjectWebhook)),
  scope: Schema.optional(Schema.NullOr(ProjectScope)),
}).annotate({ identifier: "ProjectUpdateInput" })
export type UpdatePayload = Types.DeepMutable<Schema.Schema.Type<typeof UpdatePayload>>

export class NotFoundError extends Schema.TaggedErrorClass<NotFoundError>()("Project.NotFoundError", {
  projectID: ProjectV2.ID,
}) {}

// ---------------------------------------------------------------------------
// Effect service
// ---------------------------------------------------------------------------

export interface Interface {
  /**
   * Per-instance setup. Subscribes to the `/init` slash command for the
   * current instance and stamps the project's initialized timestamp when it
   * fires. Subscription lifetime is tied to the per-instance state scope.
   */
  readonly init: () => Effect.Effect<void>
  readonly fromDirectory: (directory: string) => Effect.Effect<{ project: Info; sandbox: string }>
  readonly discover: (input: Info) => Effect.Effect<void>
  readonly list: () => Effect.Effect<Info[]>
  readonly get: (id: ProjectV2.ID) => Effect.Effect<Info | undefined>
  readonly update: (input: UpdateInput) => Effect.Effect<Info, NotFoundError>
  readonly initGit: (input: { directory: string; project: Info }) => Effect.Effect<Info>
  readonly setInitialized: (id: ProjectV2.ID) => Effect.Effect<void>
  readonly sandboxes: (id: ProjectV2.ID) => Effect.Effect<string[]>
  readonly addSandbox: (id: ProjectV2.ID, directory: string) => Effect.Effect<void>
  readonly removeSandbox: (id: ProjectV2.ID, directory: string) => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@argos/Project") {}

type GitResult = { code: number; text: string; stderr: string }

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const fs = yield* FSUtil.Service
    const proc = yield* AppProcess.Service
    const spawner = yield* ChildProcessSpawner.ChildProcessSpawner
    const projectV2 = yield* ProjectV2.Service
    const projectCopy = yield* ProjectCopy.Service
    const events = yield* EventBridge.Service
    const flags = yield* RuntimeFlags.Service
    const { db } = yield* Database.Service

    const git = Effect.fnUntraced(
      function* (args: string[], opts?: { cwd?: string }) {
        const handle = yield* spawner.spawn(
          ChildProcess.make("git", args, { cwd: opts?.cwd, extendEnv: true, stdin: "ignore" }),
        )
        const [text, stderr] = yield* Effect.all(
          [Stream.mkString(Stream.decodeText(handle.stdout)), Stream.mkString(Stream.decodeText(handle.stderr))],
          { concurrency: 2 },
        )
        const code = yield* handle.exitCode
        return { code, text, stderr } satisfies GitResult
      },
      Effect.scoped,
      Effect.catch(() => Effect.succeed({ code: 1, text: "", stderr: "" } satisfies GitResult)),
    )

    const emitUpdated = (data: Info) =>
      Effect.sync(() =>
        GlobalBus.emit("event", {
          directory: "global",
          project: data.id,
          payload: { type: Event.Updated.type, properties: data },
        }),
      )

    const fakeVcs = Schema.decodeUnknownSync(Schema.optional(ProjectVcs))(Flag.ARGOS_FAKE_VCS)

    const scope = yield* Scope.Scope

    const migrateProjectId = Effect.fn("Project.migrateProjectId")(function* (
      oldID: ProjectV2.ID | undefined,
      newID: ProjectV2.ID,
    ) {
      if (!oldID) return
      if (oldID === ProjectV2.ID.global) return
      if (oldID === newID) return

      yield* db
        .transaction(
          (d) =>
            Effect.gen(function* () {
              const oldProject = yield* d.select().from(ProjectTable).where(eq(ProjectTable.id, oldID)).get()
              const newProject = yield* d.select().from(ProjectTable).where(eq(ProjectTable.id, newID)).get()
              if (oldProject && !newProject) {
                yield* d
                  .insert(ProjectTable)
                  .values({
                    ...oldProject,
                    id: newID,
                    time_updated: Date.now(),
                  })
                  .run()
              }

              yield* d
                .update(SessionTable)
                .set({ project_id: newID, time_updated: sql`${SessionTable.time_updated}` })
                .where(eq(SessionTable.project_id, oldID))
                .run()
              yield* d
                .update(WorkspaceTable)
                .set({ project_id: newID })
                .where(eq(WorkspaceTable.project_id, oldID))
                .run()

              if (oldProject) yield* d.delete(ProjectTable).where(eq(ProjectTable.id, oldID)).run()
            }),
          { behavior: "immediate" },
        )
        .pipe(Effect.orDie)
    })

    const persistScopeToMemory = (domains?: string[], cidrs?: string[]) => {
      const targets = [...(domains ?? []), ...(cidrs ?? [])]
      if (targets.length === 0) return Effect.void
      return Effect.gen(function* () {
        try {
          const home = os.homedir()
          if (!home) return
          const envMemoryDir = process.env.ARGOS_MEMORY_DIR
          const memDirs = [
            ...(envMemoryDir ? [path.join(envMemoryDir, "findings")] : []),
            path.join(home, ".argos", "memory", "findings"),
          ]
          for (const memDir of memDirs) {
            for (const target of targets) {
              const sanitized = target.replace(/[^a-zA-Z0-9.-]/g, "_")
              const filename = `auth-${sanitized}.json`
              const isWildcard = target.startsWith("*.")
              const cleanHost = isWildcard ? target.slice(2) : target
              const authRecord = {
                title: isWildcard
                  ? `authorized engagement ${target} ${cleanHost}`
                  : `authorized engagement ${target}`,
                target: target,
                agent: "security-operator",
                kind: "authorization",
                status: "authorized",
                evidence: "Operator configured target in authorized scope via Scope Guard",
                session: "global",
                tags: ["scope", "authorized", cleanHost],
                source_tool: "scope.guard",
                time_created: Date.now(),
              }
              yield* fs
                .writeWithDirs(path.join(memDir, filename), JSON.stringify(authRecord, null, 2))
                .pipe(Effect.catch(() => Effect.void))

              if (isWildcard && cleanHost) {
                const cleanFilename = `auth-${cleanHost.replace(/[^a-zA-Z0-9.-]/g, "_")}.json`
                yield* fs
                  .writeWithDirs(path.join(memDir, cleanFilename), JSON.stringify(authRecord, null, 2))
                  .pipe(Effect.catch(() => Effect.void))
              }
            }
          }
        } catch {}
      })
    }

    const saveProjectDirectory = Effect.fn("Project.saveProjectDirectory")(function* (input: {
      projectID: ProjectV2.ID
      directory: string
    }) {
      if (input.projectID === ProjectV2.ID.global) return
      const opened = AbsolutePath.make(FSUtil.resolve(input.directory))
      const type = yield* projectCopy.detect({ directory: opened })

      yield* db
        .transaction(
          (d) =>
            Effect.gen(function* () {
              const hasMain = yield* d
                .select({ directory: ProjectDirectoryTable.directory })
                .from(ProjectDirectoryTable)
                .where(
                  and(eq(ProjectDirectoryTable.project_id, input.projectID), eq(ProjectDirectoryTable.type, "main")),
                )
                .get()
              yield* d
                .insert(ProjectDirectoryTable)
                .values({ directory: opened, project_id: input.projectID, type: type ?? (hasMain ? "root" : "main") })
                .onConflictDoNothing()
                .run()
            }),
          { behavior: "immediate" },
        )
        .pipe(
          Effect.catchCause((cause) =>
            Effect.sync(() => log.warn("project directory persistence failed", { projectID: input.projectID, cause })),
          ),
        )
    })

    const fromDirectory: Interface["fromDirectory"] = Effect.fn("Project.fromDirectory")(function* (directory: string) {
      log.info("fromDirectory", { directory })

      const data = yield* projectV2.resolve(AbsolutePath.make(directory))
      const worktree = data.id === ProjectV2.ID.make("global") && !data.vcs ? "/" : data.directory

      // Phase 2: upsert
      const projectID = ProjectV2.ID.make(data.id)
      yield* migrateProjectId(data.previous ? ProjectV2.ID.make(data.previous) : undefined, projectID)
      const row = yield* db.select().from(ProjectTable).where(eq(ProjectTable.id, projectID)).get().pipe(Effect.orDie)
      const existing = row
        ? fromRow(row)
        : {
            id: projectID,
            worktree,
            vcs: data.vcs?.type ?? fakeVcs,
            sandboxes: [] as string[],
            time: { created: Date.now(), updated: Date.now() },
          }

      if (flags.experimentalIconDiscovery) yield* discover(existing).pipe(Effect.ignore, Effect.forkIn(scope))

      const result: Info = {
        ...existing,
        worktree: projectID === ProjectV2.ID.global ? worktree : existing.worktree,
        vcs: data.vcs?.type ?? fakeVcs,
        time: { ...existing.time, updated: Date.now() },
      }
      if (
        projectID !== ProjectV2.ID.global &&
        data.directory !== result.worktree &&
        !result.sandboxes.includes(data.directory)
      )
        result.sandboxes.push(data.directory)
      result.sandboxes = yield* Effect.forEach(
        result.sandboxes,
        (s) =>
          fs.exists(s).pipe(
            Effect.orDie,
            Effect.map((exists) => (exists ? s : undefined)),
          ),
        { concurrency: "unbounded" },
      ).pipe(Effect.map((arr) => arr.filter((x): x is string => x !== undefined)))

      if (!result.scope && projectID !== ProjectV2.ID.global) {
        const argosJsonPath = path.join(data.directory, "argos.json")
        const exists = yield* fs.existsSafe(argosJsonPath)
        if (exists) {
          const content = yield* fs.readFileString(argosJsonPath).pipe(Effect.catch(() => Effect.succeed("")))
          try {
            const parsed = JSON.parse(content)
            if (parsed.scope && typeof parsed.scope === "object") {
              result.scope = {
                domains: parsed.scope.allowed_domains ?? parsed.scope.domains ?? undefined,
                cidrs: parsed.scope.allowed_cidrs ?? parsed.scope.cidrs ?? undefined,
                excluded: parsed.scope.excluded_hosts ?? parsed.scope.excluded ?? undefined,
                maxRPS: parsed.scope.max_rps ?? parsed.scope.maxRPS ?? undefined,
                maxConcurrency: parsed.scope.max_concurrency ?? parsed.scope.maxConcurrency ?? undefined,
                customHeader: parsed.scope.custom_header ?? parsed.scope.customHeader ?? undefined,
                safeMode: parsed.scope.safe_mode ?? parsed.scope.safeMode ?? undefined,
                modality: parsed.scope.modality ?? undefined,
              }
            }
          } catch {}
        }
      }

      if (result.scope) {
        yield* persistScopeToMemory(result.scope.domains, result.scope.cidrs)
      }

      yield* db
        .insert(ProjectTable)
        .values({
          id: result.id,
          worktree: AbsolutePath.make(result.worktree),
          vcs: result.vcs ?? null,
          name: result.name,
          icon_url: result.icon?.url,
          icon_url_override: result.icon?.override,
          icon_color: result.icon?.color,
          time_created: result.time.created,
          time_updated: result.time.updated,
          time_initialized: result.time.initialized,
          sandboxes: result.sandboxes.map((sandbox) => AbsolutePath.make(sandbox)),
          commands: result.commands,
          webhook: result.webhook,
          scope: result.scope,
        })
        .onConflictDoUpdate({
          target: ProjectTable.id,
          set: {
            worktree: AbsolutePath.make(result.worktree),
            vcs: result.vcs ?? null,
            name: result.name,
            icon_url: result.icon?.url,
            icon_url_override: result.icon?.override,
            icon_color: result.icon?.color,
            time_updated: result.time.updated,
            time_initialized: result.time.initialized,
            sandboxes: result.sandboxes.map((sandbox) => AbsolutePath.make(sandbox)),
            commands: result.commands,
            webhook: result.webhook,
            scope: result.scope ?? sql`${ProjectTable.scope}`,
          },
        })
        .run()
        .pipe(Effect.orDie)

      if (projectID !== ProjectV2.ID.global) {
        yield* db
          .update(SessionTable)
          .set({ project_id: projectID })
          .where(and(eq(SessionTable.project_id, ProjectV2.ID.global), eq(SessionTable.directory, data.directory)))
          .run()
          .pipe(Effect.orDie)
      }

      yield* saveProjectDirectory({
        projectID,
        directory: data.directory,
      })

      yield* emitUpdated(result)
      if (projectID !== ProjectV2.ID.global && data.vcs?.type === "git") {
        yield* projectV2.commit({ store: data.vcs.store, id: data.id })
      }
      return { project: result, sandbox: data.vcs ? data.directory : worktree }
    })

    const discover: Interface["discover"] = Effect.fn("Project.discover")(function* (input: Info) {
      if (input.vcs !== "git") return
      if (input.icon?.override) return
      if (input.icon?.url) return

      const matches = yield* fs
        .glob("**/favicon.{ico,png,svg,jpg,jpeg,webp}", {
          cwd: input.worktree,
          absolute: true,
          include: "file",
        })
        .pipe(Effect.orDie)
      const shortest = matches.sort((a, b) => a.length - b.length)[0]
      if (!shortest) return

      const buffer = yield* fs.readFile(shortest).pipe(Effect.orDie)
      const base64 = Buffer.from(buffer).toString("base64")
      const mime = FSUtil.mimeType(shortest)
      const url = `data:${mime};base64,${base64}`
      yield* update({ projectID: input.id, icon: { url } }).pipe(
        Effect.catchTag("Project.NotFoundError", () => Effect.void),
      )
    })

    const list = Effect.fn("Project.list")(function* () {
      return (yield* db.select().from(ProjectTable).all().pipe(Effect.orDie)).map(fromRow)
    })

    const get = Effect.fn("Project.get")(function* (id: ProjectV2.ID) {
      const row = yield* db.select().from(ProjectTable).where(eq(ProjectTable.id, id)).get().pipe(Effect.orDie)
      return row ? fromRow(row) : undefined
    })

    const update: Interface["update"] = Effect.fn("Project.update")(function* (input: UpdateInput) {
      const normalizedInput: UpdateInput = {
        ...input,
        directory: input.directory ? FSUtil.resolveRuntimePath(input.directory) : input.directory,
      }
      let result = yield* db
        .update(ProjectTable)
        .set({
          name: normalizedInput.name,
          icon_url: normalizedInput.icon?.url,
          icon_url_override: normalizedInput.icon?.override,
          icon_color: normalizedInput.icon?.color,
          commands: normalizedInput.commands,
          webhook: normalizedInput.webhook,
          scope: normalizedInput.scope,
          time_updated: Date.now(),
        })
        .where(eq(ProjectTable.id, normalizedInput.projectID))
        .returning()
        .get()
        .pipe(Effect.orDie)

      if (!result && normalizedInput.directory && normalizedInput.directory !== "/") {
        const normDir = AbsolutePath.make(normalizedInput.directory)
        result = yield* db
          .update(ProjectTable)
          .set({
            name: normalizedInput.name,
            icon_url: normalizedInput.icon?.url,
            icon_url_override: normalizedInput.icon?.override,
            icon_color: normalizedInput.icon?.color,
            commands: normalizedInput.commands,
            webhook: normalizedInput.webhook,
            scope: normalizedInput.scope,
            time_updated: Date.now(),
          })
          .where(eq(ProjectTable.worktree, normDir))
          .returning()
          .get()
          .pipe(Effect.orDie)
      }

      if (!result && normalizedInput.directory && normalizedInput.directory !== "/") {
        const initialized = yield* fromDirectory(normalizedInput.directory).pipe(
          Effect.catch(() => Effect.succeed(undefined)),
        )
        if (initialized) {
          result = yield* db
            .update(ProjectTable)
            .set({
              name: normalizedInput.name,
              icon_url: normalizedInput.icon?.url,
              icon_url_override: normalizedInput.icon?.override,
              icon_color: normalizedInput.icon?.color,
              commands: normalizedInput.commands,
              webhook: normalizedInput.webhook,
              scope: normalizedInput.scope,
              time_updated: Date.now(),
            })
            .where(eq(ProjectTable.id, initialized.project.id))
            .returning()
            .get()
            .pipe(Effect.orDie)
        }
      }

      if (!result) return yield* new NotFoundError({ projectID: normalizedInput.projectID })

      // Persist scope to argos.json if worktree exists
      if (normalizedInput.scope !== undefined) {
        const targetDir =
          normalizedInput.directory && normalizedInput.directory !== "/"
            ? normalizedInput.directory
            : result.worktree && result.worktree !== "/"
              ? result.worktree
              : undefined

        if (targetDir) {
          const argosJsonPath = path.join(targetDir, "argos.json")
          const exists = yield* fs.existsSafe(argosJsonPath)
          let currentConfig: Record<string, any> = {}
          if (exists) {
            const content = yield* fs.readFileString(argosJsonPath).pipe(Effect.catch(() => Effect.succeed("")))
            try {
              if (content.trim()) currentConfig = JSON.parse(content)
            } catch {}
          }
          if (normalizedInput.scope === null) {
            delete currentConfig.scope
          } else {
            currentConfig.scope = {
              allowed_domains: normalizedInput.scope.domains ?? [],
              allowed_cidrs: normalizedInput.scope.cidrs ?? [],
              excluded_hosts: normalizedInput.scope.excluded ?? [],
              max_rps: normalizedInput.scope.maxRPS ?? 0,
              max_concurrency: normalizedInput.scope.maxConcurrency ?? 0,
              custom_header: normalizedInput.scope.customHeader ?? "",
              safe_mode: normalizedInput.scope.safeMode ?? true,
              modality: normalizedInput.scope.modality ?? "black-box",
            }
          }
          if (!currentConfig["$schema"]) {
            currentConfig["$schema"] = "https://opencode.ai/config.json"
          }
          yield* fs.writeWithDirs(argosJsonPath, JSON.stringify(currentConfig, null, 2)).pipe(Effect.catch(() => Effect.void))
        }

        // Also update SessionTable so active sessions in this directory/project reflect the authorized scope
        yield* db
          .update(SessionTable)
          .set({
            scope_domains: normalizedInput.scope?.domains ?? null,
            scope_cidrs: normalizedInput.scope?.cidrs ?? null,
            scope_excluded: normalizedInput.scope?.excluded ?? null,
            scope_max_rps: normalizedInput.scope?.maxRPS ?? null,
            scope_safe_mode: normalizedInput.scope?.safeMode ?? null,
          })
          .where(
            targetDir
              ? or(
                  eq(SessionTable.directory, targetDir),
                  eq(SessionTable.project_id, result.id),
                  eq(SessionTable.project_id, normalizedInput.projectID),
                )
              : or(eq(SessionTable.project_id, result.id), eq(SessionTable.project_id, normalizedInput.projectID)),
          )
          .run()
          .pipe(Effect.catch(() => Effect.void))

        // Persist authorization memories for all in-scope domains so security agents (scout/orchestrator)
        // verifying authorization via `argos_memory_search('authorized engagement [target]')` immediately succeed
        if (normalizedInput.scope) {
          yield* persistScopeToMemory(normalizedInput.scope.domains, normalizedInput.scope.cidrs)
        }
      }

      const data = fromRow(result)
      yield* emitUpdated(data)
      return data
    })

    const initGit = Effect.fn("Project.initGit")(function* (input: { directory: string; project: Info }) {
      if (input.project.vcs === "git") return input.project
      if (!(yield* Effect.sync(() => which("git")))) throw new Error("Git is not installed")
      const result = yield* git(["init", "--quiet"], { cwd: input.directory })
      if (result.code !== 0) {
        throw new Error(result.stderr.trim() || result.text.trim() || "Failed to initialize git repository")
      }
      const { project } = yield* fromDirectory(input.directory)
      return project
    })

    const setInitialized = Effect.fn("Project.setInitialized")(function* (id: ProjectV2.ID) {
      yield* db
        .update(ProjectTable)
        .set({ time_initialized: Date.now() })
        .where(eq(ProjectTable.id, id))
        .run()
        .pipe(Effect.orDie)
    })

    const initState = yield* InstanceState.make(
      Effect.fn("Project.initState")(function* (ctx) {
        const unsubscribe = yield* events.listen((event) => {
          if (event.type !== Command.Event.Executed.type || event.location?.directory !== ctx.directory)
            return Effect.void
          const data = event.data as EventV2.Data<typeof Command.Event.Executed>
          return data.name === Command.Default.INIT ? setInitialized(ctx.project.id) : Effect.void
        })
        yield* Effect.addFinalizer(() => unsubscribe)
      }),
    )

    const init = Effect.fn("Project.init")(function* () {
      yield* InstanceState.get(initState)
    })

    const sandboxes = Effect.fn("Project.sandboxes")(function* (id: ProjectV2.ID) {
      const row = yield* db.select().from(ProjectTable).where(eq(ProjectTable.id, id)).get().pipe(Effect.orDie)
      if (!row) return []
      const data = fromRow(row)
      return yield* Effect.forEach(
        data.sandboxes,
        (dir) =>
          fs.isDir(dir).pipe(
            Effect.orDie,
            Effect.map((ok) => (ok ? dir : undefined)),
          ),
        { concurrency: "unbounded" },
      ).pipe(Effect.map((arr) => arr.filter((x): x is string => x !== undefined)))
    })

    const addSandbox = Effect.fn("Project.addSandbox")(function* (id: ProjectV2.ID, directory: string) {
      const row = yield* db.select().from(ProjectTable).where(eq(ProjectTable.id, id)).get().pipe(Effect.orDie)
      if (!row) throw new Error(`Project not found: ${id}`)
      const sandbox = AbsolutePath.make(directory)
      const sboxes = [...row.sandboxes]
      if (!sboxes.includes(sandbox)) sboxes.push(sandbox)
      const result = yield* db
        .update(ProjectTable)
        .set({ sandboxes: sboxes, time_updated: Date.now() })
        .where(eq(ProjectTable.id, id))
        .returning()
        .get()
        .pipe(Effect.orDie)
      if (!result) throw new Error(`Project not found: ${id}`)
      yield* emitUpdated(fromRow(result))
    })

    const removeSandbox = Effect.fn("Project.removeSandbox")(function* (id: ProjectV2.ID, directory: string) {
      const row = yield* db.select().from(ProjectTable).where(eq(ProjectTable.id, id)).get().pipe(Effect.orDie)
      if (!row) throw new Error(`Project not found: ${id}`)
      const sandbox = AbsolutePath.make(directory)
      const sboxes = row.sandboxes.filter((s) => s !== sandbox)
      const result = yield* db
        .update(ProjectTable)
        .set({ sandboxes: sboxes, time_updated: Date.now() })
        .where(eq(ProjectTable.id, id))
        .returning()
        .get()
        .pipe(Effect.orDie)
      if (!result) throw new Error(`Project not found: ${id}`)
      yield* emitUpdated(fromRow(result))
    })

    return Service.of({
      init,
      fromDirectory,
      discover,
      list,
      get,
      update,
      initGit,
      setInitialized,
      sandboxes,
      addSandbox,
      removeSandbox,
    })
  }),
)

export const defaultLayer = layer.pipe(
  Layer.provide(EventBridge.defaultLayer),
  Layer.provide(ProjectV2.defaultLayer),
  Layer.provide(ProjectCopy.defaultLayer),
  Layer.provide(AppProcess.defaultLayer),
  Layer.provide(CrossSpawnSpawner.defaultLayer),
  Layer.provide(FSUtil.defaultLayer),
  Layer.provide(Database.defaultLayer),
  Layer.provide(RuntimeFlags.defaultLayer),
)

export const use = serviceUse(Service)

export * as Project from "./project"
