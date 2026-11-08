export * as PtyPreparation from "./pty-preparation"

import * as InstanceState from "@/effect/instance-state"
import { Plugin } from "@/plugin"
import { Shell } from "@/shell/shell"
import { Config } from "@argos/core/config"
import { Pty } from "@argos/core/pty"
import { Effect } from "effect"

export const prepareCreate = Effect.fn("PtyPreparation.prepareCreate")(function* (input: Pty.CreateInput) {
  // Debe ser el Config de core, no el de argos: ambos se registran bajo el
  // mismo tag "@argos/Config", y el que provee LocationServiceMap (donde
  // corre este efecto) es el de core -- cuya interfaz es entries()/latest(), no
  // get(). Importar el otro compila, pero en runtime devuelve el servicio de
  // core y `config.get` queda undefined.
  const config = yield* Config.Service
  const plugin = yield* Plugin.Service
  const command = input.command || Shell.preferred(Config.latest(yield* config.entries(), "shell"))
  const args = Shell.login(command) ? [...(input.args ?? []), "-l"] : [...(input.args ?? [])]
  const cwd = input.cwd || (yield* InstanceState.context).directory
  const shell = yield* plugin.trigger("shell.env", { cwd }, { env: {} })
  const env = {
    ...process.env,
    ...input.env,
    ...shell.env,
    TERM: "xterm-256color",
    OPENCODE_TERMINAL: "1",
  } as Record<string, string>
  if (process.platform === "win32") {
    env.LC_ALL = "C.UTF-8"
    env.LC_CTYPE = "C.UTF-8"
    env.LANG = "C.UTF-8"
  }
  return { command, args, cwd, title: input.title, env }
})
