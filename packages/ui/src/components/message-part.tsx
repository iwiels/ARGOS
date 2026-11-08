import {
  Component,
  createEffect,
  createMemo,
  createSignal,
  For,
  Match,
  Show,
  Switch,
  onCleanup,
  Index,
} from "solid-js"
import { createStore } from "solid-js/store"
import { Dynamic } from "solid-js/web"
import {
  AgentPart,
  AssistantMessage,
  FilePart,
  Message as MessageType,
  Part as PartType,
  ReasoningPart,
  TextPart,
  ToolPart,
  UserMessage,
} from "@argos/sdk/client"
import { useData } from "../context"
import { useDialog } from "../context/dialog"
import { type UiI18n, useI18n } from "../context/i18n"
import { GenericTool } from "./basic-tool"
import { Collapsible } from "./collapsible"
import { FileIcon } from "./file-icon"
import { ToolErrorCard } from "./tool-error-card"
import { Markdown } from "./markdown"
import { ImagePreview } from "./image-preview"
import { getDirectory as _getDirectory, getFilename } from "@/core/path"
import { Tooltip } from "./tooltip"
import { IconButton } from "./icon-button"
import { TextShimmer } from "./text-shimmer"
import { AnimatedCountList } from "./tool-count-summary"
import { ToolStatusTitle } from "./tool-status-title"
import { useLocation } from "@solidjs/router"
import { attached, inline, kind } from "./message-file"
import { readPartText } from "./message-part-text"
import { ToolRegistry } from "./message-part-registry"
import "./message-part-tools"
import { useCopyToClipboard } from "../hooks/use-copy-to-clipboard"


export interface MessageProps {
  message: MessageType
  parts: PartType[]
  actions?: UserActions
  showAssistantCopyPartID?: string | null
  showReasoningSummaries?: boolean
}

export type SessionAction = (input: { sessionID: string; messageID: string }) => Promise<void> | void

export type UserActions = {
  fork?: SessionAction
  revert?: SessionAction
}

export interface MessagePartProps {
  part: PartType
  message: MessageType
  hideDetails?: boolean
  defaultOpen?: boolean
  toolOpen?: boolean
  onToolOpenChange?: (open: boolean) => void
  deferToolContent?: boolean
  virtualizeDiff?: boolean
  showAssistantCopyPartID?: string | null
  turnDurationMs?: number
}

export type PartComponent = Component<MessagePartProps>

export const PART_MAPPING: Record<string, PartComponent | undefined> = {}

const TEXT_RENDER_PACE_MS = 24
const TEXT_RENDER_SNAP = /[\s.,!?;:)\]]/

function step(size: number) {
  if (size <= 12) return 2
  if (size <= 48) return 4
  if (size <= 96) return 8
  return Math.min(24, Math.ceil(size / 8))
}

function next(text: string, start: number) {
  const end = Math.min(text.length, start + step(text.length - start))
  const max = Math.min(text.length, end + 8)
  for (let i = end; i < max; i++) {
    if (TEXT_RENDER_SNAP.test(text[i] ?? "")) return i + 1
  }
  return end
}

function createPacedValue(getValue: () => string, live?: () => boolean) {
  const [value, setValue] = createSignal(getValue())
  let shown = getValue()
  let timeout: ReturnType<typeof setTimeout> | undefined

  const clear = () => {
    if (!timeout) return
    clearTimeout(timeout)
    timeout = undefined
  }

  const sync = (text: string) => {
    shown = text
    setValue(text)
  }

  const run = () => {
    timeout = undefined
    const text = getValue()
    if (!live?.()) {
      sync(text)
      return
    }
    if (!text.startsWith(shown) || text.length <= shown.length) {
      sync(text)
      return
    }
    const end = next(text, shown.length)
    sync(text.slice(0, end))
    if (end < text.length) timeout = setTimeout(run, TEXT_RENDER_PACE_MS)
  }

  createEffect(() => {
    const text = getValue()
    if (!live?.()) {
      clear()
      sync(text)
      return
    }
    if (!text.startsWith(shown) || text.length < shown.length) {
      clear()
      sync(text)
      return
    }
    if (text.length === shown.length || timeout) return
    timeout = setTimeout(run, TEXT_RENDER_PACE_MS)
  })

  onCleanup(() => {
    clear()
  })

  return value
}

function PacedMarkdown(props: { text: string; cacheKey: string; streaming: boolean }) {
  const value = createPacedValue(
    () => props.text,
    () => props.streaming,
  )

  return (
    <Show when={value()}>
      <Markdown text={value()} cacheKey={props.cacheKey} streaming={props.streaming} />
    </Show>
  )
}

export function relativizeProjectPath(path: string, directory?: string) {
  if (!path) return ""
  if (!directory) return path
  if (directory === "/") return path
  if (directory === "\\") return path
  if (path === directory) return ""

  const separator = directory.includes("\\") ? "\\" : "/"
  const prefix = directory.endsWith(separator) ? directory : directory + separator
  if (!path.startsWith(prefix)) return path
  return path.slice(directory.length)
}

export function getDirectory(path: string | undefined) {
  const data = useData()
  return relativizeProjectPath(_getDirectory(path), data.directory)
}

import type { IconProps } from "./icon"

export type ToolInfo = {
  icon: IconProps["name"]
  title: string
  subtitle?: string
}

function agentTitle(i18n: UiI18n, type?: string) {
  if (!type) return i18n.t("ui.tool.agent.default")
  return i18n.t("ui.tool.agent", { type })
}


export function webSearchProviderLabel(provider: unknown) {
  if (provider === "parallel") return "Parallel Web Search"
  if (provider === "exa") return "Exa Web Search"
  return "Web Search"
}

export function getToolInfo(
  tool: string,
  input: any = {},
  metadata: Record<string, unknown> | undefined = {},
): ToolInfo {
  const i18n = useI18n()
  switch (tool) {
    case "read":
      return {
        icon: "glasses",
        title: i18n.t("ui.tool.read"),
        subtitle: input.filePath ? getFilename(input.filePath) : undefined,
      }
    case "list":
      return {
        icon: "bullet-list",
        title: i18n.t("ui.tool.list"),
        subtitle: input.path ? getFilename(input.path) : undefined,
      }
    case "glob":
      return {
        icon: "magnifying-glass",
        title: i18n.t("ui.tool.glob"),
        subtitle: input.pattern,
      }
    case "grep":
      return {
        icon: "magnifying-glass",
        title: i18n.t("ui.tool.grep"),
        subtitle: input.pattern,
      }
    case "webfetch":
      return {
        icon: "window-cursor",
        title: i18n.t("ui.tool.webfetch"),
        subtitle: input.url,
      }
    case "websearch":
      return {
        icon: "window-cursor",
        title: webSearchProviderLabel(metadata?.provider),
        subtitle: input.query,
      }
    case "task": {
      const type =
        typeof input.subagent_type === "string" && input.subagent_type
          ? input.subagent_type[0]!.toUpperCase() + input.subagent_type.slice(1)
          : undefined
      return {
        icon: "task",
        title: agentTitle(i18n, type),
        subtitle: input.description,
      }
    }
    case "bash":
      return {
        icon: "console",
        title: i18n.t("ui.tool.shell"),
        subtitle: input.description,
      }
    case "edit":
      return {
        icon: "code-lines",
        title: i18n.t("ui.messagePart.title.edit"),
        subtitle: input.filePath ? getFilename(input.filePath) : undefined,
      }
    case "write":
      return {
        icon: "code-lines",
        title: i18n.t("ui.messagePart.title.write"),
        subtitle: input.filePath ? getFilename(input.filePath) : undefined,
      }
    case "apply_patch":
      return {
        icon: "code-lines",
        title: i18n.t("ui.tool.patch"),
        subtitle: input.files?.length
          ? `${input.files.length} ${i18n.t(input.files.length > 1 ? "ui.common.file.other" : "ui.common.file.one")}`
          : undefined,
      }
    case "todowrite":
      return {
        icon: "checklist",
        title: i18n.t("ui.tool.todos"),
      }
    case "question":
      return {
        icon: "help-circle",
        title: i18n.t("ui.tool.questions"),
      }
    case "skill":
      return {
        icon: "brain",
        title: input.name || i18n.t("ui.tool.skill"),
      }
    default: {
      const parts = tool.split("_")
      const action = parts[parts.length - 1] || tool
      let icon: any = "mcp"
      const lowerAction = action.toLowerCase()
      if (lowerAction.includes("search") || lowerAction.includes("find")) {
        icon = "magnifying-glass"
      } else if (lowerAction.includes("read") || lowerAction.includes("get") || lowerAction.includes("list")) {
        icon = "glasses"
      } else if (lowerAction.includes("write") || lowerAction.includes("create") || lowerAction.includes("edit") || lowerAction.includes("update")) {
        icon = "code-lines"
      }

      let title = action
        .split(/(?=[A-Z])|_/)
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(" ")
        .trim()
        
      if (!title) title = tool

      return {
        icon,
        title,
      }
    }
  }
}


export function sessionLink(id: string | undefined, path: string, href?: (id: string) => string | undefined) {
  if (!id) return

  const direct = href?.(id)
  if (direct) return direct

  const idx = path.indexOf("/session")
  if (idx === -1) return
  return `${path.slice(0, idx)}/session/${id}`
}


const CONTEXT_GROUP_TOOLS = new Set(["read", "glob", "grep", "list"])
const HIDDEN_TOOLS = new Set(["todowrite"])

function list<T>(value: T[] | undefined | null, fallback: T[]) {
  if (Array.isArray(value)) return value
  return fallback
}

function same<T>(a: readonly T[] | undefined, b: readonly T[] | undefined) {
  if (a === b) return true
  if (!a || !b) return false
  if (a.length !== b.length) return false
  return a.every((x, i) => x === b[i])
}

export type PartRef = {
  messageID: string
  partID: string
}

export type PartGroup =
  | {
      key: string
      type: "part"
      ref: PartRef
    }
  | {
      key: string
      type: "context"
      refs: PartRef[]
    }

function sameRef(a: PartRef, b: PartRef) {
  return a.messageID === b.messageID && a.partID === b.partID
}

function sameGroup(a: PartGroup, b: PartGroup) {
  if (a === b) return true
  if (a.key !== b.key) return false
  if (a.type !== b.type) return false
  if (a.type === "part") {
    if (b.type !== "part") return false
    return sameRef(a.ref, b.ref)
  }
  if (b.type !== "context") return false
  if (a.refs.length !== b.refs.length) return false
  return a.refs.every((ref, i) => sameRef(ref, b.refs[i]))
}

export function sameGroups(a: readonly PartGroup[] | undefined, b: readonly PartGroup[] | undefined) {
  if (a === b) return true
  if (!a || !b) return false
  if (a.length !== b.length) return false
  return a.every((item, i) => sameGroup(item, b[i]))
}

export function groupParts(parts: { messageID: string; part: PartType }[]) {
  const result: PartGroup[] = []
  let start = -1

  const flush = (end: number) => {
    if (start < 0) return
    const first = parts[start]
    const last = parts[end]
    if (!first || !last) {
      start = -1
      return
    }
    result.push({
      key: `context:${first.part.id}`,
      type: "context",
      refs: parts.slice(start, end + 1).map((item) => ({
        messageID: item.messageID,
        partID: item.part.id,
      })),
    })
    start = -1
  }

  parts.forEach((item, index) => {
    if (isContextGroupTool(item.part)) {
      if (start < 0) start = index
      return
    }

    flush(index - 1)
    result.push({
      key: `part:${item.messageID}:${item.part.id}`,
      type: "part",
      ref: {
        messageID: item.messageID,
        partID: item.part.id,
      },
    })
  })

  flush(parts.length - 1)
  return result
}

function index<T extends { id: string }>(items: readonly T[]) {
  return new Map(items.map((item) => [item.id, item] as const))
}

export function renderable(part: PartType, showReasoningSummaries = true) {
  if (part.type === "tool") {
    if (HIDDEN_TOOLS.has(part.tool)) return false
    if (part.tool === "question") return part.state.status !== "pending" && part.state.status !== "running"
    return true
  }
  if (part.type === "text") return !!part.text?.trim()
  if (part.type === "reasoning") return showReasoningSummaries && !!part.text?.trim()
  return !!PART_MAPPING[part.type]
}

function toolDefaultOpen(tool: string, shell = false, edit = false) {
  if (tool === "bash") return shell
  if (tool === "edit" || tool === "write" || tool === "apply_patch") return edit
}

export function partDefaultOpen(part: PartType, shell = false, edit = false) {
  if (part.type !== "tool") return
  return toolDefaultOpen(part.tool, shell, edit)
}

export function AssistantParts(props: {
  messages: AssistantMessage[]
  showAssistantCopyPartID?: string | null
  turnDurationMs?: number
  working?: boolean
  showReasoningSummaries?: boolean
  shellToolDefaultOpen?: boolean
  editToolDefaultOpen?: boolean
}) {
  const data = useData()
  const emptyParts: PartType[] = []
  const emptyTools: ToolPart[] = []
  const msgs = createMemo(() => index(props.messages))
  const part = createMemo(
    () =>
      new Map(
        props.messages.map((message) => [message.id, index(list(data.store.part?.[message.id], emptyParts))] as const),
      ),
  )

  const grouped = createMemo(
    () =>
      groupParts(
        props.messages.flatMap((message) =>
          list(data.store.part?.[message.id], emptyParts)
            .filter((part) => renderable(part, props.showReasoningSummaries ?? true))
            .map((part) => ({
              messageID: message.id,
              part,
            })),
        ),
      ),
    [] as PartGroup[],
    { equals: sameGroups },
  )

  const last = createMemo(() => grouped().at(-1)?.key)

  return (
    <Index each={grouped()}>
      {(entryAccessor) => {
        const entryType = createMemo(() => entryAccessor().type)

        return (
          <Switch>
            <Match when={entryType() === "context"}>
              {(() => {
                const parts = createMemo(
                  () => {
                    const entry = entryAccessor()
                    if (entry.type !== "context") return emptyTools
                    return entry.refs
                      .map((ref) => part().get(ref.messageID)?.get(ref.partID))
                      .filter((part): part is ToolPart => !!part && isContextGroupTool(part))
                  },
                  emptyTools,
                  { equals: same },
                )
                const busy = createMemo(() => props.working && last() === entryAccessor().key)

                return (
                  <Show when={parts().length > 0}>
                    <ContextToolGroup parts={parts()} busy={busy()} />
                  </Show>
                )
              })()}
            </Match>
            <Match when={entryType() === "part"}>
              {(() => {
                const message = createMemo(() => {
                  const entry = entryAccessor()
                  if (entry.type !== "part") return
                  return msgs().get(entry.ref.messageID)
                })
                const item = createMemo(() => {
                  const entry = entryAccessor()
                  if (entry.type !== "part") return
                  return part().get(entry.ref.messageID)?.get(entry.ref.partID)
                })

                return (
                  <Show when={message()}>
                    <Show when={item()}>
                      <Part
                        part={item()!}
                        message={message()!}
                        showAssistantCopyPartID={props.showAssistantCopyPartID}
                        turnDurationMs={props.turnDurationMs}
                        defaultOpen={partDefaultOpen(item()!, props.shellToolDefaultOpen, props.editToolDefaultOpen)}
                      />
                    </Show>
                  </Show>
                )
              })()}
            </Match>
          </Switch>
        )
      }}
    </Index>
  )
}

function isContextGroupTool(part: PartType): part is ToolPart {
  return part.type === "tool" && CONTEXT_GROUP_TOOLS.has(part.tool)
}

function contextToolDetail(part: ToolPart): string | undefined {
  const info = getToolInfo(
    part.tool,
    part.state.input ?? {},
    "metadata" in part.state ? part.state.metadata : undefined,
  )
  if (info.subtitle) return info.subtitle
  if (part.state.status === "error") return part.state.error
  if ((part.state.status === "running" || part.state.status === "completed") && part.state.title)
    return part.state.title
  const description = part.state.input?.description
  if (typeof description === "string") return description
  return undefined
}

function contextToolTrigger(part: ToolPart, i18n: ReturnType<typeof useI18n>) {
  const input = (part.state.input ?? {}) as Record<string, unknown>
  const path = typeof input.path === "string" ? input.path : "/"
  const filePath = typeof input.filePath === "string" ? input.filePath : undefined
  const pattern = typeof input.pattern === "string" ? input.pattern : undefined
  const include = typeof input.include === "string" ? input.include : undefined
  const offset = typeof input.offset === "number" ? input.offset : undefined
  const limit = typeof input.limit === "number" ? input.limit : undefined

  switch (part.tool) {
    case "read": {
      const args: string[] = []
      if (offset !== undefined) args.push("offset=" + offset)
      if (limit !== undefined) args.push("limit=" + limit)
      return {
        title: i18n.t("ui.tool.read"),
        subtitle: filePath ? getFilename(filePath) : "",
        args,
      }
    }
    case "list":
      return {
        title: i18n.t("ui.tool.list"),
        subtitle: getDirectory(path),
      }
    case "glob":
      return {
        title: i18n.t("ui.tool.glob"),
        subtitle: getDirectory(path),
        args: pattern ? ["pattern=" + pattern] : [],
      }
    case "grep": {
      const args: string[] = []
      if (pattern) args.push("pattern=" + pattern)
      if (include) args.push("include=" + include)
      return {
        title: i18n.t("ui.tool.grep"),
        subtitle: getDirectory(path),
        args,
      }
    }
    default: {
      const info = getToolInfo(part.tool, input, "metadata" in part.state ? part.state.metadata : undefined)
      return {
        title: info.title,
        subtitle: info.subtitle || contextToolDetail(part),
        args: [],
      }
    }
  }
}

function contextToolSummary(parts: ToolPart[]) {
  const read = parts.filter((part) => part.tool === "read").length
  const search = parts.filter((part) => part.tool === "glob" || part.tool === "grep").length
  const list = parts.filter((part) => part.tool === "list").length
  return { read, search, list }
}


export function registerPartComponent(type: string, component: PartComponent) {
  PART_MAPPING[type] = component
}

export function Message(props: MessageProps) {
  return (
    <Switch>
      <Match when={props.message.role === "user" && props.message}>
        {(userMessage) => (
          <UserMessageDisplay message={userMessage()} parts={props.parts} actions={props.actions} />
        )}
      </Match>
      <Match when={props.message.role === "assistant" && props.message}>
        {(assistantMessage) => (
          <AssistantMessageDisplay
            message={assistantMessage()}
            parts={props.parts}
            showAssistantCopyPartID={props.showAssistantCopyPartID}
            showReasoningSummaries={props.showReasoningSummaries}
          />
        )}
      </Match>
    </Switch>
  )
}

export function AssistantMessageDisplay(props: {
  message: AssistantMessage
  parts: PartType[]
  showAssistantCopyPartID?: string | null
  showReasoningSummaries?: boolean
}) {
  const emptyTools: ToolPart[] = []
  const part = createMemo(() => index(props.parts))
  const grouped = createMemo(
    () =>
      groupParts(
        props.parts
          .filter((part) => renderable(part, props.showReasoningSummaries ?? true))
          .map((part) => ({
            messageID: props.message.id,
            part,
          })),
      ),
    [] as PartGroup[],
    { equals: sameGroups },
  )

  return (
    <Index each={grouped()}>
      {(entryAccessor) => {
        const entryType = createMemo(() => entryAccessor().type)

        return (
          <Switch>
            <Match when={entryType() === "context"}>
              {(() => {
                const parts = createMemo(
                  () => {
                    const entry = entryAccessor()
                    if (entry.type !== "context") return emptyTools
                    return entry.refs
                      .map((ref) => part().get(ref.partID))
                      .filter((part): part is ToolPart => !!part && isContextGroupTool(part))
                  },
                  emptyTools,
                  { equals: same },
                )

                return (
                  <Show when={parts().length > 0}>
                    <ContextToolGroup parts={parts()} />
                  </Show>
                )
              })()}
            </Match>
            <Match when={entryType() === "part"}>
              {(() => {
                const item = createMemo(() => {
                  const entry = entryAccessor()
                  if (entry.type !== "part") return
                  return part().get(entry.ref.partID)
                })

                return (
                  <Show when={item()}>
                    <Part
                      part={item()!}
                      message={props.message}
                      showAssistantCopyPartID={props.showAssistantCopyPartID}
                    />
                  </Show>
                )
              })()}
            </Match>
          </Switch>
        )
      }}
    </Index>
  )
}

export function ContextToolGroup(props: { parts: ToolPart[]; busy?: boolean; onSizeChange?: () => void }) {
  const i18n = useI18n()
  const [open, setOpen] = createSignal(false)
  const pending = createMemo(
    () =>
      !!props.busy || props.parts.some((part) => part.state.status === "pending" || part.state.status === "running"),
  )
  const summary = createMemo(() => contextToolSummary(props.parts))
  const handleOpenChange = (value: boolean) => {
    setOpen(value)
    props.onSizeChange?.()
  }

  return (
    <Collapsible
      open={open()}
      onOpenChange={handleOpenChange}
      variant="ghost"
      class="tool-collapsible"
      data-timeline-part-ids={props.parts.map((part) => part.id).join(",")}
    >
      <Collapsible.Trigger>
        <div data-component="context-tool-group-trigger">
          <span
            data-slot="context-tool-group-title"
            class="min-w-0 flex items-center gap-2 text-14-medium text-text-strong"
          >
            <span data-slot="context-tool-group-label" class="shrink-0">
              <ToolStatusTitle
                active={pending()}
                activeText={i18n.t("ui.sessionTurn.status.gatheringContext")}
                doneText={i18n.t("ui.sessionTurn.status.gatheredContext")}
                split={false}
              />
            </span>
            <span
              data-slot="context-tool-group-summary"
              class="min-w-0 overflow-hidden text-ellipsis whitespace-nowrap font-normal text-text-base"
            >
              <AnimatedCountList
                items={[
                  {
                    key: "read",
                    count: summary().read,
                    one: i18n.t("ui.messagePart.context.read.one"),
                    other: i18n.t("ui.messagePart.context.read.other"),
                  },
                  {
                    key: "search",
                    count: summary().search,
                    one: i18n.t("ui.messagePart.context.search.one"),
                    other: i18n.t("ui.messagePart.context.search.other"),
                  },
                  {
                    key: "list",
                    count: summary().list,
                    one: i18n.t("ui.messagePart.context.list.one"),
                    other: i18n.t("ui.messagePart.context.list.other"),
                  },
                ]}
                fallback=""
              />
            </span>
          </span>
          <Collapsible.Arrow />
        </div>
      </Collapsible.Trigger>
      <Collapsible.Content>
        <div data-component="context-tool-group-list">
          <Index each={props.parts}>
            {(partAccessor) => {
              const trigger = createMemo(() => contextToolTrigger(partAccessor(), i18n))
              const running = createMemo(
                () => partAccessor().state.status === "pending" || partAccessor().state.status === "running",
              )
              return (
                <div data-slot="context-tool-group-item" class="min-w-0 w-full overflow-hidden">
                  <div data-component="tool-trigger" class="min-w-0 w-full overflow-hidden">
                    <div data-slot="basic-tool-tool-trigger-content" class="min-w-0 w-full overflow-hidden">
                      <div data-slot="basic-tool-tool-info" class="min-w-0 w-full overflow-hidden">
                        <div data-slot="basic-tool-tool-info-structured" class="flex items-center gap-2 min-w-0 max-w-full overflow-hidden flex-nowrap">
                          <div data-slot="basic-tool-tool-info-main" class="flex items-center gap-2 min-w-0 max-w-full overflow-hidden flex-nowrap">
                            <span data-slot="basic-tool-tool-title" class="shrink-0 font-medium text-13 whitespace-nowrap">
                              <TextShimmer text={trigger().title} active={running()} />
                            </span>
                            <Show when={!running() && trigger().subtitle}>
                              <span data-slot="basic-tool-tool-subtitle" title={trigger().subtitle} class="min-w-0 truncate text-13 font-normal">{trigger().subtitle}</span>
                            </Show>
                            <Show when={!running() && trigger().args?.length}>
                              <For each={trigger().args}>
                                {(arg) => <span data-slot="basic-tool-tool-arg" title={arg} class="min-w-0 truncate text-12 font-mono text-text-secondary shrink">{arg}</span>}
                              </For>
                            </Show>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )
            }}
          </Index>
        </div>
      </Collapsible.Content>
    </Collapsible>
  )
}

export function UserMessageDisplay(props: { message: UserMessage; parts: PartType[]; actions?: UserActions }) {
  const data = useData()
  const dialog = useDialog()
  const i18n = useI18n()
  const [state, setState] = createStore({
    busy: false,
  })
  const { copied, copy: copyToClipboard } = useCopyToClipboard()
  const busy = () => state.busy

  const textPart = createMemo(
    () => props.parts?.find((p) => p.type === "text" && !p.synthetic) as TextPart | undefined,
  )

  const text = createMemo(() => textPart()?.text || "")

  const files = createMemo(() => props.parts?.filter((p) => p.type === "file") ?? [])

  const attachments = createMemo(() => files().filter(attached))

  const inlineFiles = createMemo(() => files().filter(inline))

  const agents = createMemo(() => props.parts?.filter((p) => p.type === "agent") ?? [])

  const model = createMemo(() => {
    const providerID = props.message.model?.providerID
    const modelID = props.message.model?.modelID
    if (!providerID || !modelID) return ""
    const match = data.store.provider?.all?.get(providerID)
    return match?.models?.[modelID]?.name ?? modelID
  })
  const timefmt = createMemo(() => new Intl.DateTimeFormat(i18n.locale(), { timeStyle: "short" }))

  const stamp = createMemo(() => {
    const created = props.message.time?.created
    if (typeof created !== "number") return ""
    return timefmt().format(created)
  })

  const metaHead = createMemo(() => {
    const agent = props.message.agent
    const items = [agent ? agent[0]?.toUpperCase() + agent.slice(1) : "", model()]
    return items.filter((x) => !!x).join("\u00A0\u00B7\u00A0")
  })

  const metaTail = stamp

  const openImagePreview = (url: string, alt?: string) => {
    void dialog.show(() => <ImagePreview src={url} alt={alt} />)
  }

  const handleCopy = async () => {
    const content = text()
    if (!content) return
    await copyToClipboard(content)
  }

  const revert = () => {
    const act = props.actions?.revert
    if (!act || busy()) return
    setState("busy", true)
    void Promise.resolve()
      .then(() =>
        act({
          sessionID: props.message.sessionID,
          messageID: props.message.id,
        }),
      )
      .finally(() => setState("busy", false))
  }

  return (
    <div data-component="user-message" data-timeline-part-id={textPart()?.id}>
      <Show when={attachments().length > 0}>
        <div data-slot="user-message-attachments">
          <For each={attachments()}>
            {(file) => {
              const type = kind(file)
              const name = file.filename ?? i18n.t("ui.message.attachment.alt")

              return (
                <div
                  data-slot="user-message-attachment"
                  data-type={type}
                  data-clickable={type === "image" ? "true" : undefined}
                  title={type === "file" ? name : undefined}
                  onClick={() => {
                    if (type === "image") openImagePreview(file.url, name)
                  }}
                >
                  <Show
                    when={type === "image"}
                    fallback={
                      <div data-slot="user-message-attachment-file">
                        <FileIcon node={{ path: name, type: "file" }} />
                        <span data-slot="user-message-attachment-name">{name}</span>
                      </div>
                    }
                  >
                    <img data-slot="user-message-attachment-image" src={file.url} alt={name} />
                  </Show>
                </div>
              )
            }}
          </For>
        </div>
      </Show>
      <Show when={text()}>
        <>
          <div data-slot="user-message-body">
            <div data-slot="user-message-text">
              <HighlightedText text={text()} references={inlineFiles()} agents={agents()} />
            </div>
          </div>
          <div data-slot="user-message-copy-wrapper">
            <Show when={metaHead() || metaTail()}>
              <span data-slot="user-message-meta-wrap">
                <Show when={metaHead()}>
                  <span data-slot="user-message-meta" class="text-12-regular text-text-weak cursor-default">
                    {metaHead()}
                  </span>
                </Show>
                <Show when={metaHead() && metaTail()}>
                  <span data-slot="user-message-meta-sep" class="text-12-regular text-text-weak cursor-default">
                    {"\u00A0\u00B7\u00A0"}
                  </span>
                </Show>
                <Show when={metaTail()}>
                  <span data-slot="user-message-meta-tail" class="text-12-regular text-text-weak cursor-default">
                    {metaTail()}
                  </span>
                </Show>
              </span>
            </Show>
            <Show when={props.actions?.revert}>
              <Tooltip value={i18n.t("ui.message.revertMessage")} placement="top" gutter={4}>
                <IconButton
                  icon="reset"
                  size="normal"
                  variant="ghost"
                  disabled={busy()}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={(event) => {
                    event.stopPropagation()
                    revert()
                  }}
                  aria-label={i18n.t("ui.message.revertMessage")}
                />
              </Tooltip>
            </Show>
            <Tooltip
              value={copied() ? i18n.t("ui.message.copied") : i18n.t("ui.message.copyMessage")}
              placement="top"
              gutter={4}
            >
              <IconButton
                icon={copied() ? "check" : "copy"}
                size="normal"
                variant="ghost"
                onMouseDown={(e) => e.preventDefault()}
                onClick={(event) => {
                  event.stopPropagation()
                  void handleCopy()
                }}
                aria-label={copied() ? i18n.t("ui.message.copied") : i18n.t("ui.message.copyMessage")}
              />
            </Tooltip>
          </div>
        </>
      </Show>
    </div>
  )
}

type HighlightSegment = { text: string; type?: "file" | "agent" }

function HighlightedText(props: { text: string; references: FilePart[]; agents: AgentPart[] }) {
  const segments = createMemo(() => {
    const text = props.text

    const allRefs: { start: number; end: number; type: "file" | "agent" }[] = [
      ...props.references
        .filter((r) => r.source?.text?.start !== undefined && r.source?.text?.end !== undefined)
        .map((r) => ({ start: r.source!.text.start, end: r.source!.text.end, type: "file" as const })),
      ...props.agents
        .filter((a) => a.source?.start !== undefined && a.source?.end !== undefined)
        .map((a) => ({ start: a.source!.start, end: a.source!.end, type: "agent" as const })),
    ].sort((a, b) => a.start - b.start)

    const result: HighlightSegment[] = []
    let lastIndex = 0

    for (const ref of allRefs) {
      if (ref.start < lastIndex) continue

      if (ref.start > lastIndex) {
        result.push({ text: text.slice(lastIndex, ref.start) })
      }

      result.push({ text: text.slice(ref.start, ref.end), type: ref.type })
      lastIndex = ref.end
    }

    if (lastIndex < text.length) {
      result.push({ text: text.slice(lastIndex) })
    }

    return result
  })

  return <For each={segments()}>{(segment) => <span data-highlight={segment.type}>{segment.text}</span>}</For>
}

export function Part(props: MessagePartProps) {
  const component = createMemo(() => PART_MAPPING[props.part.type])
  return (
    <Show when={component()}>
      <Dynamic
        component={component()}
        part={props.part}
        message={props.message}
        hideDetails={props.hideDetails}
        defaultOpen={props.defaultOpen}
        toolOpen={props.toolOpen}
        onToolOpenChange={props.onToolOpenChange}
        deferToolContent={props.deferToolContent}
        virtualizeDiff={props.virtualizeDiff}
        showAssistantCopyPartID={props.showAssistantCopyPartID}
        turnDurationMs={props.turnDurationMs}
      />
    </Show>
  )
}



PART_MAPPING["tool"] = function ToolPartDisplay(props) {
  const data = useData()
  const i18n = useI18n()
  const part = () => props.part as ToolPart
  if (part().tool === "todowrite") return null

  const hideQuestion = createMemo(
    () => part().tool === "question" && (part().state.status === "pending" || part().state.status === "running"),
  )

  const emptyInput: Record<string, any> = {}
  const emptyMetadata: Record<string, any> = {}

  const input = () => part().state?.input ?? emptyInput
  // @ts-expect-error
  const partMetadata = () => part().state?.metadata ?? emptyMetadata
  const taskId = createMemo(() => {
    if (part().tool !== "task") return
    const value = partMetadata().sessionId
    if (typeof value === "string" && value) return value
  })
  const taskHref = createMemo(() => {
    if (part().tool !== "task") return
    return sessionLink(taskId(), useLocation().pathname, data.sessionHref)
  })
  const taskSubtitle = createMemo(() => {
    if (part().tool !== "task") return undefined
    const value = input().description
    if (typeof value === "string" && value) return value
    return taskId()
  })
  
  const getToolSubtitle = createMemo(() => {
    if (taskSubtitle()) return taskSubtitle()
    if (part().tool === "bash") {
      return input().command ?? partMetadata().command
    }
    if (part().tool === "read" || part().tool === "list" || part().tool === "glob" || part().tool === "grep" || part().tool === "file_search") {
      return input().path ?? input().pattern ?? input().filePath
    }
    if (part().tool === "websearch") return input().query
    if (part().tool === "webfetch") return input().url
    if (part().tool === "apply_patch") return input().filePath ?? input().path
    return undefined
  })

  const render = createMemo(() => ToolRegistry.render(part().tool) ?? GenericTool)
  const controlledOpen = () => (props.onToolOpenChange ? (props.toolOpen ?? props.defaultOpen) : undefined)
  const handleToolOpenChange = (open: boolean) => props.onToolOpenChange?.(open)

  return (
    <Show when={!hideQuestion()}>
      <div data-component="tool-part-wrapper" data-timeline-part-id={part().id}>
        <Switch>
          <Match when={part().state.status === "error" && (part().state as any).error}>
            {(error) => {
              const cleaned = error().replace("Error: ", "")
              if (part().tool === "question" && cleaned.includes("dismissed this question")) {
                return (
                  <div style="width: 100%; display: flex; justify-content: flex-end;">
                    <span class="text-13-regular text-text-weak cursor-default">
                      {i18n.t("ui.messagePart.questions.dismissed")}
                    </span>
                  </div>
                )
              }
              return (
                <ToolErrorCard
                  tool={part().tool}
                  error={error()}
                  title={part().tool === "websearch" ? webSearchProviderLabel(partMetadata().provider) : undefined}
                  defaultOpen={props.defaultOpen}
                  open={controlledOpen()}
                  onOpenChange={props.onToolOpenChange ? handleToolOpenChange : undefined}
                  subtitle={getToolSubtitle()}
                  href={taskHref()}
                />
              )
            }}
          </Match>
          <Match when={true}>
            <Dynamic
              component={render()}
              input={input()}
              tool={part().tool}
              sessionID={part().sessionID}
              metadata={partMetadata()}
              // @ts-expect-error
              output={part().state.output}
              status={part().state.status}
              hideDetails={props.hideDetails}
              defaultOpen={props.defaultOpen}
              open={controlledOpen()}
              onOpenChange={props.onToolOpenChange ? handleToolOpenChange : undefined}
              deferContent={props.deferToolContent}
              virtualizeDiff={props.virtualizeDiff}
            />
          </Match>
        </Switch>
      </div>
    </Show>
  )
}

export function MessageDivider(props: { label: string }) {
  return (
    <div data-component="compaction-part">
      <div data-slot="compaction-part-divider">
        <span data-slot="compaction-part-line" />
        <span data-slot="compaction-part-label" class="text-12-regular text-text-weak">
          {props.label}
        </span>
        <span data-slot="compaction-part-line" />
      </div>
    </div>
  )
}

PART_MAPPING["compaction"] = function CompactionPartDisplay() {
  const i18n = useI18n()
  return <MessageDivider label={i18n.t("ui.messagePart.compaction")} />
}

PART_MAPPING["text"] = function TextPartDisplay(props) {
  const data = useData()
  const i18n = useI18n()
  const numfmt = createMemo(() => new Intl.NumberFormat(i18n.locale()))
  const part = () => props.part as TextPart
  const interrupted = createMemo(
    () =>
      props.message.role === "assistant" && props.message.error?.name === "MessageAbortedError",
  )

  const model = createMemo(() => {
    if (props.message.role !== "assistant") return ""
    const message = props.message
    const match = data.store.provider?.all?.get(message.providerID)
    return match?.models?.[message.modelID]?.name ?? message.modelID
  })

  const duration = createMemo(() => {
    if (props.message.role !== "assistant") return ""
    const message = props.message
    const completed = message.time.completed
    const ms =
      typeof props.turnDurationMs === "number"
        ? props.turnDurationMs
        : typeof completed === "number"
          ? completed - message.time.created
          : -1
    if (!(ms >= 0)) return ""
    const total = Math.round(ms / 1000)
    if (total < 60) return i18n.t("ui.message.duration.seconds", { count: numfmt().format(total) })
    const minutes = Math.floor(total / 60)
    const seconds = total % 60
    return i18n.t("ui.message.duration.minutesSeconds", {
      minutes: numfmt().format(minutes),
      seconds: numfmt().format(seconds),
    })
  })

  const meta = createMemo(() => {
    if (props.message.role !== "assistant") return ""
    const agent = props.message.agent
    const items = [
      agent ? agent[0]?.toUpperCase() + agent.slice(1) : "",
      model(),
      duration(),
      interrupted() ? i18n.t("ui.message.interrupted") : "",
    ]
    return items.filter((x) => !!x).join(" \u00B7 ")
  })

  const streaming = createMemo(
    () => props.message.role === "assistant" && typeof props.message.time.completed !== "number",
  )
  const text = () => readPartText(data.store.part_text_accum_delta, part())
  const isLastTextPart = createMemo(() => {
    const last = (data.store.part?.[props.message.id] ?? [])
      .filter((item): item is TextPart => item?.type === "text" && !!item.text?.trim())
      .at(-1)
    return last?.id === part().id
  })
  const showCopy = createMemo(() => {
    if (props.message.role !== "assistant") return isLastTextPart()
    if (props.showAssistantCopyPartID === null) return false
    if (typeof props.showAssistantCopyPartID === "string") return props.showAssistantCopyPartID === part().id
    return isLastTextPart()
  })
  const { copied, copy: copyToClipboard } = useCopyToClipboard()

  const handleCopy = async () => {
    const content = text()
    if (!content) return
    await copyToClipboard(content)
  }

  return (
    <Show when={text()}>
      <div data-component="text-part" data-timeline-part-id={part().id}>
        <div data-slot="text-part-body">
          <Show when={streaming()} fallback={<Markdown text={text()} cacheKey={part().id} streaming={false} />}>
            <PacedMarkdown text={text()} cacheKey={part().id} streaming={streaming()} />
          </Show>
        </div>
        <Show when={showCopy()}>
          <div data-slot="text-part-copy-wrapper" data-interrupted={interrupted() ? "" : undefined}>
            <Tooltip
              value={copied() ? i18n.t("ui.message.copied") : i18n.t("ui.message.copyResponse")}
              placement="top"
              gutter={4}
            >
              <IconButton
                icon={copied() ? "check" : "copy"}
                size="normal"
                variant="ghost"
                onMouseDown={(e) => e.preventDefault()}
                onClick={handleCopy}
                aria-label={copied() ? i18n.t("ui.message.copied") : i18n.t("ui.message.copyResponse")}
              />
            </Tooltip>
            <Show when={meta()}>
              <span data-slot="text-part-meta" class="text-12-regular text-text-weak cursor-default">
                {meta()}
              </span>
            </Show>
          </div>
        </Show>
      </div>
    </Show>
  )
}

PART_MAPPING["reasoning"] = function ReasoningPartDisplay(props) {
  const data = useData()
  const part = () => props.part as ReasoningPart
  const streaming = createMemo(
    () => props.message.role === "assistant" && typeof props.message.time.completed !== "number",
  )
  const text = () => readPartText(data.store.part_text_accum_delta, part())

  return (
    <Show when={text()}>
      <div data-component="reasoning-part" data-timeline-part-id={part().id}>
        <Show when={streaming()} fallback={<Markdown text={text()} cacheKey={part().id} streaming={false} />}>
          <PacedMarkdown text={text()} cacheKey={part().id} streaming={streaming()} />
        </Show>
      </div>
    </Show>
  )
}
