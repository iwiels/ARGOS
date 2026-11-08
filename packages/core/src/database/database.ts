export * as Database from "./database"

import { EffectDrizzleSqlite } from "@argos/effect-drizzle-sqlite"
import { layer as sqliteLayer } from "#sqlite"
import { Context, Effect, Layer } from "effect"
import { Global } from "../global"
import { Flag } from "../flag/flag"
import { isAbsolute, join } from "path"
import { DatabaseMigration } from "./migration"
import { InstallationChannel } from "../installation/version"

const makeDatabase = EffectDrizzleSqlite.makeWithDefaults()
type DatabaseShape = Effect.Success<typeof makeDatabase>

export interface Interface {
  db: DatabaseShape
}

export class Service extends Context.Service<Service, Interface>()("@argos/storage/Database") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const db = yield* makeDatabase

    yield* db.run("PRAGMA journal_mode = WAL")
    yield* db.run("PRAGMA synchronous = NORMAL")
    yield* db.run("PRAGMA busy_timeout = 5000")
    yield* db.run("PRAGMA cache_size = -64000")
    yield* db.run("PRAGMA foreign_keys = ON")
    yield* DatabaseMigration.apply(db)

    type TableInfo = { name: string }[]
    const tableInfo = yield* db.run("PRAGMA table_info(session_context_epoch)").pipe(Effect.catch(() => Effect.succeed([] as unknown as TableInfo)))
    if (tableInfo.length > 0) {
      const columns = tableInfo.map((row: any) => row.name)
      if (!columns.includes("replacement_seq")) {
        yield* db.run("ALTER TABLE session_context_epoch ADD COLUMN replacement_seq INTEGER").pipe(Effect.catch(() => Effect.void))
      }
      if (!columns.includes("agent")) {
        yield* db.run("ALTER TABLE session_context_epoch ADD COLUMN agent TEXT DEFAULT 'build' NOT NULL").pipe(Effect.catch(() => Effect.void))
      }
      if (!columns.includes("revision")) {
        yield* db.run("ALTER TABLE session_context_epoch ADD COLUMN revision INTEGER DEFAULT 0 NOT NULL").pipe(Effect.catch(() => Effect.void))
      }
    }

    return { db }
  }).pipe(Effect.orDie),
)

export function layerFromPath(filename: string) {
  return layer.pipe(Layer.provide(sqliteLayer({ filename })))
}

export function path() {
  if (Flag.ARGOS_DB) {
    if (Flag.ARGOS_DB === ":memory:" || isAbsolute(Flag.ARGOS_DB)) return Flag.ARGOS_DB
    return join(Global.Path.data, Flag.ARGOS_DB)
  }
  if (
    ["latest", "beta", "prod"].includes(InstallationChannel) ||
    process.env.OPENCODE_DISABLE_CHANNEL_DB === "1" ||
    process.env.OPENCODE_DISABLE_CHANNEL_DB === "true"
  )
    return join(Global.Path.data, "opencode.db")
  return join(Global.Path.data, `opencode-${InstallationChannel.replace(/[^a-zA-Z0-9._-]/g, "-")}.db`)
}

export const defaultLayer = Layer.unwrap(
  Effect.gen(function* () {
    return layerFromPath(path())
  }),
).pipe(Layer.provide(Global.defaultLayer))
