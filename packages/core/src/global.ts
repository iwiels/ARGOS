import path from "path"
import fs from "fs/promises"
import { existsSync } from "fs"
import { xdgData, xdgCache, xdgConfig, xdgState } from "xdg-basedir"
import os from "os"
import { Context, Effect, Layer } from "effect"
import { Flock } from "./util/flock"
import { Flag } from "./flag/flag"

const app = "argos"
const legacyApp = "opencode"

function resolveDir(base: string | undefined, name: string, fallbackName?: string) {
  const primary = base ? path.join(base, name) : path.join(os.homedir(), `.${name}`)
  if (fallbackName) {
    const fallback = base ? path.join(base, fallbackName) : path.join(os.homedir(), `.${fallbackName}`)
    if (!existsSync(primary) && existsSync(fallback)) {
      return fallback
    }
  }
  return primary
}

const data = resolveDir(xdgData, app, legacyApp)
const cache = resolveDir(xdgCache, app, legacyApp)
const config = resolveDir(xdgConfig, app, legacyApp)
const state = resolveDir(xdgState, app, legacyApp)
const tmp = path.join(os.tmpdir(), app)

const paths = {
  get home() {
    return process.env.ARGOS_TEST_HOME ?? process.env.OPENCODE_TEST_HOME ?? os.homedir()
  },
  data,
  bin: path.join(cache, "bin"),
  log: path.join(data, "log"),
  repos: path.join(data, "repos"),
  cache,
  config,
  state,
  tmp,
}

export const Path = paths

Flock.setGlobal({ state })

await Promise.all([
  fs.mkdir(Path.data, { recursive: true }),
  fs.mkdir(Path.config, { recursive: true }),
  fs.mkdir(Path.state, { recursive: true }),
  fs.mkdir(Path.tmp, { recursive: true }),
  fs.mkdir(Path.log, { recursive: true }),
  fs.mkdir(Path.bin, { recursive: true }),
  fs.mkdir(Path.repos, { recursive: true }),
])

export class Service extends Context.Service<Service, Interface>()("@argos/Global") {}

export interface Interface {
  readonly home: string
  readonly data: string
  readonly cache: string
  readonly config: string
  readonly state: string
  readonly tmp: string
  readonly bin: string
  readonly log: string
  readonly repos: string
}

export function make(input: Partial<Interface> = {}): Interface {
  return {
    home: Path.home,
    data: Path.data,
    cache: Path.cache,
    config: Flag.ARGOS_CONFIG_DIR ?? Path.config,
    state: Path.state,
    tmp: Path.tmp,
    bin: Path.bin,
    log: Path.log,
    repos: Path.repos,
    ...input,
  }
}

export const layer = Layer.effect(
  Service,
  Effect.sync(() => Service.of(make())),
)

export const defaultLayer = layer

export const layerWith = (input: Partial<Interface>) =>
  Layer.effect(
    Service,
    Effect.sync(() => Service.of(make(input))),
  )

export * as Global from "./global"
