import { NodePath } from "@effect/platform-node"
import { Cause, Duration, Effect, Layer, Option, Schedule, Context } from "effect"
import path from "path"
import type { Agent } from "../agent/agent"
import { FSUtil } from "@argos/core/fs-util"
import { evaluate } from "@/permission/evaluate"
import { Config } from "@/config/config"
import { Identifier } from "../id/id"
import * as Log from "@argos/core/util/log"
import { ToolID } from "./schema"
import { TRUNCATION_DIR } from "./truncation-dir"

const log = Log.create({ service: "truncation" })
const RETENTION = Duration.days(7)

export const MAX_LINES = 2000
export const MAX_BYTES = 50 * 1024
export const DIR = TRUNCATION_DIR
export const GLOB = path.join(TRUNCATION_DIR, "*")

const takePrefix = (input: string, maximumBytes: number) => {
  let bytes = 0
  let content = ""
  for (const char of input) {
    const size = Buffer.byteLength(char, "utf-8")
    if (bytes + size > maximumBytes) break
    content += char
    bytes += size
  }
  return content
}

const takeSuffix = (input: string, maximumBytes: number) => {
  let bytes = 0
  const content: string[] = []
  for (const char of Array.from(input).toReversed()) {
    const size = Buffer.byteLength(char, "utf-8")
    if (bytes + size > maximumBytes) break
    content.unshift(char)
    bytes += size
  }
  return content.join("")
}

export type Result = { content: string; truncated: false } | { content: string; truncated: true; outputPath: string }

export interface Options {
  maxLines?: number
  maxBytes?: number
  direction?: "head" | "tail" | "head-tail"
}

function hasTaskTool(agent?: Agent.Info) {
  if (!agent?.permission) return false
  return evaluate("task", "*", agent.permission).action !== "deny"
}

export interface Interface {
  readonly cleanup: () => Effect.Effect<void>
  readonly write: (text: string) => Effect.Effect<string>
  /**
   * Returns output unchanged when it fits within the limits, otherwise writes the full text
   * to the truncation directory and returns a preview plus a hint to inspect the saved file.
   */
  readonly output: (text: string, options?: Options, agent?: Agent.Info) => Effect.Effect<Result>
  /**
   * Resolved truncation limits: values from `tool_output` in opencode config, or MAX_LINES / MAX_BYTES if unset.
   */
  readonly limits: () => Effect.Effect<{ maxLines: number; maxBytes: number }>
}

export class Service extends Context.Service<Service, Interface>()("@argos/Truncate") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const fs = yield* FSUtil.Service

    const cleanup = Effect.fn("Truncate.cleanup")(function* () {
      const cutoff = Identifier.timestamp(
        Identifier.create("tool", "ascending", Date.now() - Duration.toMillis(RETENTION)),
      )
      const entries = yield* fs.readDirectory(TRUNCATION_DIR).pipe(
        Effect.map((all) => all.filter((name) => name.startsWith("tool_"))),
        Effect.catch(() => Effect.succeed([])),
      )
      for (const entry of entries) {
        if (Identifier.timestamp(entry) >= cutoff) continue
        yield* fs.remove(path.join(TRUNCATION_DIR, entry)).pipe(Effect.catch(() => Effect.void))
      }
    })

    const write = Effect.fn("Truncate.write")(function* (text: string) {
      const file = path.join(TRUNCATION_DIR, ToolID.ascending())
      yield* fs.ensureDir(TRUNCATION_DIR).pipe(Effect.orDie)
      yield* fs.writeFileString(file, text).pipe(Effect.orDie)
      return file
    })

    const limits = Effect.fn("Truncate.limits")(function* () {
      const configSvc = yield* Effect.serviceOption(Config.Service)
      if (Option.isNone(configSvc)) return { maxLines: MAX_LINES, maxBytes: MAX_BYTES }
      const cfg = yield* configSvc.value.get().pipe(Effect.catch(() => Effect.succeed(undefined)))
      return {
        maxLines: cfg?.tool_output?.max_lines ?? MAX_LINES,
        maxBytes: cfg?.tool_output?.max_bytes ?? MAX_BYTES,
      }
    })

    const output = Effect.fn("Truncate.output")(function* (text: string, options: Options = {}, agent?: Agent.Info) {
      const resolved = yield* limits()
      const maxLines = options.maxLines ?? resolved.maxLines
      const maxBytes = options.maxBytes ?? resolved.maxBytes
      const direction = options.direction ?? "head-tail"
      const lines = text.split("\n")
      const totalBytes = Buffer.byteLength(text, "utf-8")

      if (lines.length <= maxLines && totalBytes <= maxBytes) {
        return { content: text, truncated: false } as const
      }

      // Head+tail sampling by default (like ToolOutputStore in core): split the
      // budget between the start and the end of the output so the model keeps
      // the opening context AND the final findings. Explicit "head"/"tail"
      // directions keep the old single-side cut for callers that need it.
      const headLines = direction === "tail" ? 0 : direction === "head" ? maxLines : Math.ceil(maxLines / 2)
      const tailLines = direction === "head" ? 0 : direction === "tail" ? maxLines : Math.floor(maxLines / 2)
      const headBytes = direction === "tail" ? 0 : direction === "head" ? maxBytes : Math.ceil(maxBytes / 2)
      const tailBytes = direction === "head" ? 0 : direction === "tail" ? maxBytes : Math.floor(maxBytes / 2)

      const head: string[] = []
      let headBytesUsed = 0
      let hitBytes = false
      for (let i = 0; i < lines.length && head.length < headLines; i++) {
        const size = Buffer.byteLength(lines[i], "utf-8") + (head.length > 0 ? 1 : 0)
        if (headBytesUsed + size > headBytes) {
          hitBytes = true
          break
        }
        head.push(lines[i])
        headBytesUsed += size
      }

      const tail: string[] = []
      let tailBytesUsed = 0
      for (let i = lines.length - 1; i >= 0 && tail.length < tailLines; i--) {
        const size = Buffer.byteLength(lines[i], "utf-8") + (tail.length > 0 ? 1 : 0)
        if (tailBytesUsed + size > tailBytes) {
          hitBytes = true
          break
        }
        tail.unshift(lines[i])
        tailBytesUsed += size
      }

      // When no whole line fits either budget (e.g. a single minified JSON from
      // an MCP scan), fall back to byte-slicing the text like ToolOutputStore so
      // the model still sees the head and tail of the content instead of nothing.
      const previewHead = head.length > 0 ? head.join("\n") : takePrefix(text, headBytes)
      const previewTail = tail.length > 0 ? tail.join("\n") : takeSuffix(text, tailBytes)
      const shown = previewTail ? `${previewHead}\n\n${previewTail}` : previewHead
      const omittedLines = lines.length - head.length - tail.length
      const omittedBytes = Math.max(0, totalBytes - Buffer.byteLength(shown, "utf-8"))
      const removed = hitBytes ? omittedBytes : omittedLines
      const unit = hitBytes ? "bytes" : "lines"
      const file = yield* write(text)

      const hint = hasTaskTool(agent)
        ? `The tool call succeeded but the output was truncated. Full output saved to: ${file}\nUse the Task tool to have explore agent process this file with Grep and Read (with offset/limit). Do NOT read the full file yourself - delegate to save context.`
        : `The tool call succeeded but the output was truncated. Full output saved to: ${file}\nUse Grep to search the full content or Read with offset/limit to view specific sections.`

      const marker = `...${removed} ${unit} truncated...`
      const content =
        direction === "head"
          ? `${previewHead}\n\n${marker}\n\n${hint}`
          : direction === "tail"
            ? `${marker}\n\n${hint}\n\n${previewTail}`
            : previewHead
              ? `${previewHead}\n\n${marker}${previewTail ? `\n\n${previewTail}` : ""}\n\n${hint}`
              : `${marker}\n\n${hint}${previewTail ? `\n\n${previewTail}` : ""}`

      return {
        content,
        truncated: true,
        outputPath: file,
      } as const
    })

    yield* cleanup().pipe(
      Effect.catchCause((cause) => {
        log.error("truncation cleanup failed", { cause: Cause.pretty(cause) })
        return Effect.void
      }),
      Effect.repeat(Schedule.spaced(Duration.hours(1))),
      Effect.delay(Duration.minutes(1)),
      Effect.forkScoped,
    )

    return Service.of({ cleanup, write, output, limits })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(FSUtil.defaultLayer), Layer.provide(NodePath.layer))

export * as Truncate from "./truncate"
