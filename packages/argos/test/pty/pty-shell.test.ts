import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
// PtyPreparation corre dentro de LocationServiceMap, que provee el Config de
// CORE (interfaz `entries()`), no el de argos (interfaz `get()`). Ambos se
// registran bajo el mismo tag "@argos/Config", así que mockear el de
// argos compilaba y pasaba en verde mientras producción devolvía 500.
import { Config } from "@argos/core/config"
import { Plugin } from "../../src/plugin"
import { PtyPreparation } from "../../src/pty-preparation"
import { Pty } from "@argos/core/pty"
import { Shell } from "../../src/shell/shell"
import { testEffect } from "../lib/effect"

Shell.preferred.reset()

const pluginMock = Layer.mock(Plugin.Service)({
  trigger: <Name extends string, Input, Output>(_name: Name, _input: Input, output: Output) => Effect.succeed(output),
  list: () => Effect.succeed([]),
  init: () => Effect.void,
})

/** Capa de Config de core con el `shell` que se quiera configurar (o ninguno). */
const configMock = (shell?: string) =>
  Layer.mock(Config.Service)({
    entries: () => Effect.succeed(shell ? [new Config.Document({ type: "document", info: { shell } })] : []),
  })

const it = testEffect(Layer.mergeAll(configMock(), pluginMock))

const preparationIt = testEffect(
  Layer.mergeAll(
    configMock(),
    Layer.mock(Plugin.Service)({
      trigger: <Name extends string, Input, Output>(_name: Name, _input: Input, output: Output) =>
        Effect.sync(() => {
          const result = output as { env: Record<string, string> }
          result.env.INPUT = "plugin"
          result.env.FROM_PLUGIN = "plugin"
          result.env.TERM = "plugin"
          return output
        }),
      list: () => Effect.succeed([]),
      init: () => Effect.void,
    }),
  ),
)

const preparePty = (input: Pty.CreateInput) => PtyPreparation.prepareCreate(input)

describe("pty shell args", () => {
  if (process.platform !== "win32") return

  const ps = Bun.which("pwsh") || Bun.which("powershell")
  if (ps) {
    it.instance(
      "does not add login args to pwsh",
      () =>
        Effect.gen(function* () {
          const info = yield* preparePty({ command: ps, title: "pwsh" })
          expect(info.args).toEqual([])
        }),
      { timeout: 30000 },
    )
  }

  const bash = (() => {
    const shell = Shell.preferred()
    if (Shell.name(shell) === "bash") return shell
    return Shell.gitbash()
  })()
  if (bash) {
    it.instance(
      "adds login args to bash",
      () =>
        Effect.gen(function* () {
          const info = yield* preparePty({ command: bash, title: "bash" })
          expect(info.args).toEqual(["-l"])
        }),
      { timeout: 30000 },
    )
  }
})

describe("pty configured shell", () => {
  const configured = process.platform === "win32" ? Bun.which("pwsh") || Bun.which("powershell") : Bun.which("bash")

  if (configured) {
    // El shell configurado llega por Config.entries() -> Config.latest(_, "shell"),
    // que es exactamente la ruta que usa producción.
    const configuredIt = testEffect(Layer.mergeAll(configMock(Shell.name(configured)), pluginMock))

    configuredIt.instance(
      "uses configured shell for default PTY command",
      () =>
        Effect.gen(function* () {
          const info = yield* preparePty({ title: "configured" })
          if (process.platform === "win32") {
            expect(info.command.toLowerCase()).toBe(configured.toLowerCase())
          } else {
            expect(info.command).toBe(configured)
          }
          expect(info.args).toEqual(process.platform === "win32" ? [] : ["-l"])
        }),
      { timeout: 30000 },
    )
  }
})

describe("pty environment preparation", () => {
  preparationIt.instance("merges plugin environment before forced PTY values", () =>
    Effect.gen(function* () {
      const input = { command: "/bin/sh", args: [] as string[], env: { INPUT: "caller" } }
      const prepared = yield* preparePty(input)

      expect(input.args).toEqual([])
      expect(prepared.env.INPUT).toBe("plugin")
      expect(prepared.env.FROM_PLUGIN).toBe("plugin")
      expect(prepared.env.TERM).toBe("xterm-256color")
      expect(prepared.env.OPENCODE_TERMINAL).toBe("1")
    }),
  )
})
