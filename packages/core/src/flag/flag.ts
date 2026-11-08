import { Config } from "effect"

export function getEnv(key: string): string | undefined {
  if (key.startsWith("ARGOS_")) {
    const val = process.env[key]
    if (val !== undefined) return val
    const opencodeKey = "OPENCODE_" + key.slice("ARGOS_".length)
    return process.env[opencodeKey]
  }
  if (key.startsWith("OPENCODE_")) {
    const argosKey = "ARGOS_" + key.slice("OPENCODE_".length)
    const argosVal = process.env[argosKey]
    if (argosVal !== undefined) return argosVal
    return process.env[key]
  }
  return process.env[key]
}

export function truthy(key: string) {
  const value = getEnv(key)?.toLowerCase()
  return value === "true" || value === "1"
}

const copy = getEnv("ARGOS_EXPERIMENTAL_DISABLE_COPY_ON_SELECT")

function enabledByExperimental(key: string) {
  return getEnv(key) === undefined ? truthy("ARGOS_EXPERIMENTAL") || truthy("OPENCODE_EXPERIMENTAL") : truthy(key)
}

export const Flag = {
  OTEL_EXPORTER_OTLP_ENDPOINT: process.env["OTEL_EXPORTER_OTLP_ENDPOINT"],
  OTEL_EXPORTER_OTLP_HEADERS: process.env["OTEL_EXPORTER_OTLP_HEADERS"],

  ARGOS_AUTO_HEAP_SNAPSHOT: truthy("ARGOS_AUTO_HEAP_SNAPSHOT"),
  ARGOS_GIT_BASH_PATH: getEnv("ARGOS_GIT_BASH_PATH"),
  ARGOS_DISABLE_AUTOUPDATE: truthy("ARGOS_DISABLE_AUTOUPDATE"),
  ARGOS_ALWAYS_NOTIFY_UPDATE: truthy("ARGOS_ALWAYS_NOTIFY_UPDATE"),
  ARGOS_DISABLE_PRUNE: truthy("ARGOS_DISABLE_PRUNE"),
  ARGOS_DISABLE_TERMINAL_TITLE: truthy("ARGOS_DISABLE_TERMINAL_TITLE"),
  ARGOS_SHOW_TTFD: truthy("ARGOS_SHOW_TTFD"),
  ARGOS_DISABLE_AUTOCOMPACT: truthy("ARGOS_DISABLE_AUTOCOMPACT"),
  ARGOS_DISABLE_MODELS_FETCH: truthy("ARGOS_DISABLE_MODELS_FETCH"),
  ARGOS_DISABLE_MOUSE: truthy("ARGOS_DISABLE_MOUSE"),
  ARGOS_FAKE_VCS: getEnv("ARGOS_FAKE_VCS"),
  ARGOS_SERVER_PASSWORD: getEnv("ARGOS_SERVER_PASSWORD"),
  ARGOS_SERVER_USERNAME: getEnv("ARGOS_SERVER_USERNAME"),

  // Experimental
  ARGOS_EXPERIMENTAL_FILEWATCHER: Config.boolean("ARGOS_EXPERIMENTAL_FILEWATCHER").pipe(
    Config.orElse(() => Config.boolean("OPENCODE_EXPERIMENTAL_FILEWATCHER")),
    Config.withDefault(false),
  ),
  ARGOS_EXPERIMENTAL_DISABLE_FILEWATCHER: Config.boolean("ARGOS_EXPERIMENTAL_DISABLE_FILEWATCHER").pipe(
    Config.orElse(() => Config.boolean("OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER")),
    Config.withDefault(false),
  ),
  ARGOS_EXPERIMENTAL_DISABLE_COPY_ON_SELECT:
    copy === undefined ? process.platform === "win32" : truthy("ARGOS_EXPERIMENTAL_DISABLE_COPY_ON_SELECT"),
  ARGOS_MODELS_URL: getEnv("ARGOS_MODELS_URL"),
  ARGOS_MODELS_PATH: getEnv("ARGOS_MODELS_PATH"),
  ARGOS_DB: getEnv("ARGOS_DB"),

  ARGOS_WORKSPACE_ID: getEnv("ARGOS_WORKSPACE_ID"),
  ARGOS_EXPERIMENTAL_WORKSPACES: enabledByExperimental("ARGOS_EXPERIMENTAL_WORKSPACES"),
  ARGOS_EXPERIMENTAL_SESSION_SWITCHER: enabledByExperimental("ARGOS_EXPERIMENTAL_SESSION_SWITCHER"),

  // Evaluated at access time (not module load) because tests, the CLI, and
  // external tooling set these env vars at runtime.
  get ARGOS_DISABLE_PROJECT_CONFIG() {
    return truthy("ARGOS_DISABLE_PROJECT_CONFIG")
  },
  get ARGOS_EXPERIMENTAL_REFERENCES() {
    return enabledByExperimental("ARGOS_EXPERIMENTAL_REFERENCES")
  },
  get ARGOS_TUI_CONFIG() {
    return getEnv("ARGOS_TUI_CONFIG")
  },
  get ARGOS_CONFIG() {
    return getEnv("ARGOS_CONFIG")
  },
  get ARGOS_CONFIG_CONTENT() {
    return getEnv("ARGOS_CONFIG_CONTENT")
  },
  get ARGOS_CONFIG_DIR() {
    return getEnv("ARGOS_CONFIG_DIR")
  },
  get ARGOS_PURE() {
    return truthy("ARGOS_PURE")
  },
  get ARGOS_PERMISSION() {
    return getEnv("ARGOS_PERMISSION")
  },
  get ARGOS_PLUGIN_META_FILE() {
    return getEnv("ARGOS_PLUGIN_META_FILE")
  },
  get ARGOS_CLIENT() {
    return getEnv("ARGOS_CLIENT") ?? "cli"
  },

  // Legacy OPENCODE_* compatibility accessors
  get OPENCODE_AUTO_HEAP_SNAPSHOT() {
    return this.ARGOS_AUTO_HEAP_SNAPSHOT
  },
  get OPENCODE_GIT_BASH_PATH() {
    return this.ARGOS_GIT_BASH_PATH
  },
  get OPENCODE_CONFIG() {
    return this.ARGOS_CONFIG
  },
  get OPENCODE_CONFIG_CONTENT() {
    return this.ARGOS_CONFIG_CONTENT
  },
  get OPENCODE_DISABLE_AUTOUPDATE() {
    return this.ARGOS_DISABLE_AUTOUPDATE
  },
  get OPENCODE_ALWAYS_NOTIFY_UPDATE() {
    return this.ARGOS_ALWAYS_NOTIFY_UPDATE
  },
  get OPENCODE_DISABLE_PRUNE() {
    return this.ARGOS_DISABLE_PRUNE
  },
  get OPENCODE_DISABLE_TERMINAL_TITLE() {
    return this.ARGOS_DISABLE_TERMINAL_TITLE
  },
  get OPENCODE_SHOW_TTFD() {
    return this.ARGOS_SHOW_TTFD
  },
  get OPENCODE_DISABLE_AUTOCOMPACT() {
    return this.ARGOS_DISABLE_AUTOCOMPACT
  },
  get OPENCODE_DISABLE_MODELS_FETCH() {
    return this.ARGOS_DISABLE_MODELS_FETCH
  },
  get OPENCODE_DISABLE_MOUSE() {
    return this.ARGOS_DISABLE_MOUSE
  },
  get OPENCODE_FAKE_VCS() {
    return this.ARGOS_FAKE_VCS
  },
  get OPENCODE_SERVER_PASSWORD() {
    return this.ARGOS_SERVER_PASSWORD
  },
  set OPENCODE_SERVER_PASSWORD(v: string | undefined) {
    this.ARGOS_SERVER_PASSWORD = v
  },
  get OPENCODE_SERVER_USERNAME() {
    return this.ARGOS_SERVER_USERNAME
  },
  set OPENCODE_SERVER_USERNAME(v: string | undefined) {
    this.ARGOS_SERVER_USERNAME = v
  },
  get OPENCODE_EXPERIMENTAL_FILEWATCHER() {
    return this.ARGOS_EXPERIMENTAL_FILEWATCHER
  },
  get OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER() {
    return this.ARGOS_EXPERIMENTAL_DISABLE_FILEWATCHER
  },
  get OPENCODE_EXPERIMENTAL_DISABLE_COPY_ON_SELECT() {
    return this.ARGOS_EXPERIMENTAL_DISABLE_COPY_ON_SELECT
  },
  get OPENCODE_MODELS_URL() {
    return this.ARGOS_MODELS_URL
  },
  get OPENCODE_MODELS_PATH() {
    return this.ARGOS_MODELS_PATH
  },
  get OPENCODE_DB() {
    return this.ARGOS_DB
  },
  set OPENCODE_DB(v: string | undefined) {
    this.ARGOS_DB = v
  },
  get OPENCODE_WORKSPACE_ID() {
    return this.ARGOS_WORKSPACE_ID
  },
  set OPENCODE_WORKSPACE_ID(v: string | undefined) {
    this.ARGOS_WORKSPACE_ID = v
  },
  get OPENCODE_EXPERIMENTAL_WORKSPACES() {
    return this.ARGOS_EXPERIMENTAL_WORKSPACES
  },
  get OPENCODE_EXPERIMENTAL_SESSION_SWITCHER() {
    return this.ARGOS_EXPERIMENTAL_SESSION_SWITCHER
  },
  get OPENCODE_DISABLE_PROJECT_CONFIG() {
    return this.ARGOS_DISABLE_PROJECT_CONFIG
  },
  get OPENCODE_EXPERIMENTAL_REFERENCES() {
    return this.ARGOS_EXPERIMENTAL_REFERENCES
  },
  get OPENCODE_TUI_CONFIG() {
    return this.ARGOS_TUI_CONFIG
  },
  get OPENCODE_CONFIG_DIR() {
    return this.ARGOS_CONFIG_DIR
  },
  get OPENCODE_PURE() {
    return this.ARGOS_PURE
  },
  get OPENCODE_PERMISSION() {
    return this.ARGOS_PERMISSION
  },
  get OPENCODE_PLUGIN_META_FILE() {
    return this.ARGOS_PLUGIN_META_FILE
  },
  get OPENCODE_CLIENT() {
    return this.ARGOS_CLIENT
  },
}
