import {
  createEffect,
  createMemo,
  createSignal,
  For,
  Match,
  Show,
  Switch,
  type JSX,
} from "solid-js"
import { Dynamic } from "solid-js/web"
import stripAnsi from "strip-ansi"
import { useLocation } from "@solidjs/router"
import type { QuestionAnswer, QuestionInfo, Session, Todo } from "@argos/sdk/client"
import { useData } from "../context"
import { useFileComponent } from "../context/file"
import { useI18n } from "../context/i18n"
import { BasicTool } from "./basic-tool"
import { Accordion } from "./accordion"
import { StickyAccordionHeader } from "./sticky-accordion-header"
import { FileIcon } from "./file-icon"
import { Icon } from "./icon"
import { Checkbox } from "./checkbox"
import { DiffChanges } from "./diff-changes"
import { Markdown } from "./markdown"
import { Tooltip } from "./tooltip"
import { IconButton } from "./icon-button"
import { TextShimmer } from "./text-shimmer"
import { patchFiles } from "./apply-patch-file"
import { getFilename } from "@/core/path"
import { checksum } from "@/core/encode"
import { resolveFileDiff } from "./session-diff"
import { ToolRegistry } from "./message-part-registry"
import { getDirectory, relativizeProjectPath, sessionLink, webSearchProviderLabel } from "./message-part"
import { useCopyToClipboard } from "../hooks/use-copy-to-clipboard"

interface Diagnostic {
  range: {
    start: { line: number; character: number }
    end: { line: number; character: number }
  }
  message: string
  severity?: number
}

function getDiagnostics(
  diagnosticsByFile: Record<string, Diagnostic[]> | undefined,
  filePath: string | undefined,
): Diagnostic[] {
  if (!diagnosticsByFile || !filePath) return []
  const diagnostics = diagnosticsByFile[filePath] ?? []
  return diagnostics.filter((d) => d.severity === 1).slice(0, 3)
}

function DiagnosticsDisplay(props: { diagnostics: Diagnostic[] }): JSX.Element {
  const i18n = useI18n()
  return (
    <Show when={props.diagnostics.length > 0}>
      <div data-component="diagnostics">
        <For each={props.diagnostics}>
          {(diagnostic) => (
            <div data-slot="diagnostic">
              <span data-slot="diagnostic-label">{i18n.t("ui.messagePart.diagnostic.error")}</span>
              <span data-slot="diagnostic-location">
                [{diagnostic.range.start.line + 1}:{diagnostic.range.start.character + 1}]
              </span>
              <span data-slot="diagnostic-message">{diagnostic.message}</span>
            </div>
          )}
        </For>
      </div>
    </Show>
  )
}

const agentTones: Record<string, string> = {
  ask: "var(--icon-agent-ask-base)",
  build: "var(--icon-agent-build-base)",
  docs: "var(--icon-agent-docs-base)",
  plan: "var(--icon-agent-plan-base)",
  analyst: "var(--icon-agent-analyst-base)",
  triage: "var(--icon-agent-triage-base)",
  hunter: "var(--icon-agent-hunter-base)",
  responder: "var(--icon-agent-responder-base)",
}

const agentPalette = [
  "var(--icon-agent-ask-base)",
  "var(--icon-agent-build-base)",
  "var(--icon-agent-docs-base)",
  "var(--icon-agent-plan-base)",
  "var(--icon-agent-analyst-base)",
  "var(--icon-agent-triage-base)",
  "var(--icon-agent-hunter-base)",
  "var(--icon-agent-responder-base)",
  "var(--syntax-info)",
  "var(--syntax-success)",
  "var(--syntax-warning)",
  "var(--syntax-property)",
  "var(--syntax-constant)",
  "var(--text-diff-add-base)",
  "var(--text-diff-delete-base)",
  "var(--icon-warning-base)",
]

function tone(name: string) {
  let hash = 0
  for (const char of name) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return agentPalette[hash % agentPalette.length]
}

function taskAgent(
  raw: unknown,
  list?: readonly { name: string; color?: string }[],
): { name?: string; color?: string } {
  if (typeof raw !== "string" || !raw) return {}
  const key = raw.toLowerCase()
  const item = list?.find((entry) => entry.name === raw || entry.name.toLowerCase() === key)
  return {
    name: item?.name ?? `${raw[0].toUpperCase()}${raw.slice(1)}`,
    color: item?.color ?? agentTones[key] ?? tone(key),
  }
}

function urls(text: string | undefined) {
  if (!text) return []
  const seen = new Set<string>()
  return [...text.matchAll(/https?:\/\/[^\s<>"'`)\]]+/g)]
    .map((item) => item[0].replace(/[),.;:!?]+$/g, ""))
    .filter((item) => {
      if (seen.has(item)) return false
      seen.add(item)
      return true
    })
}

function currentSession(path: string) {
  return path.match(/\/session\/([^/?#]+)/)?.[1]
}

function taskSession(
  input: Record<string, any>,
  path: string,
  sessions: Session[] | undefined,
  agents?: readonly { name: string; color?: string }[],
) {
  const parentID = currentSession(path)
  if (!parentID) return
  const description = typeof input.description === "string" ? input.description : ""
  const agent = taskAgent(input.subagent_type, agents).name
  return (sessions ?? [])
    .filter((session) => session.parentID === parentID && !session.time?.archived)
    .filter((session) => (description ? session.title.startsWith(description) : true))
    .filter((session) => (agent ? session.title.includes(`@${agent}`) : true))
    .sort((a, b) => (b.time.created ?? 0) - (a.time.created ?? 0))[0]?.id
}

function parseLinkInfo(url: string) {
  try {
    const parsed = new URL(url)
    const host = parsed.hostname.replace(/^www\./, "")
    let title = parsed.pathname.replace(/^\/|\/$/g, "")
    if (parsed.hash) {
      title += parsed.hash
    }
    if (!title) {
      title = host
    } else if (host === "github.com" || host === "gitlab.com") {
      const parts = title.split("/").filter(Boolean)
      if (parts.length >= 2) {
        title = `${parts[0]} / ${parts[1]}` + (parts.length > 2 ? ` (${parts.slice(2).join("/")})` : "")
      }
    }
    const isCode = host.includes("github") || host.includes("gitlab") || host.includes("bitbucket")
    const isDoc = host.includes("doc") || parsed.pathname.includes("doc") || host.includes("developer")
    return {
      url,
      host,
      title,
      isCode,
      isDoc,
    }
  } catch {
    return {
      url,
      host: url,
      title: url,
      isCode: false,
      isDoc: false,
    }
  }
}

function ExaOutput(props: { output?: string }) {
  const links = createMemo(() => urls(props.output).map(parseLinkInfo))
  const [showAll, setShowAll] = createSignal(false)
  const initialLimit = 8
  const displayedLinks = createMemo(() => {
    const all = links()
    if (showAll() || all.length <= initialLimit) return all
    return all.slice(0, initialLimit)
  })

  return (
    <Show when={links().length > 0}>
      <div data-component="exa-tool-output" class="flex flex-col gap-2.5 p-3 rounded-lg border border-border-weaker-base bg-bg-surface/50">
        {/* Header summary */}
        <div class="flex items-center justify-between text-xs text-text-tertiary pb-1.5 border-b border-border-weaker-base/60">
          <span class="flex items-center gap-1.5 font-medium text-text-secondary">
            <Icon name="globe" class="size-3.5 text-text-tertiary" />
            <span>Resultados web encontrados ({links().length})</span>
          </span>
          <span class="text-[11px] font-mono text-text-tertiary">
            {links().length} fuentes
          </span>
        </div>

        {/* Links grid */}
        <div data-slot="exa-tool-links" class="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-[360px] overflow-y-auto pr-1">
          <For each={displayedLinks()}>
            {(item) => (
              <a
                data-slot="exa-tool-link"
                href={item.url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(event) => event.stopPropagation()}
                class="group flex items-start gap-2.5 p-2.5 rounded-md border border-border-weaker-base/70 bg-bg-surface hover:border-border-strong hover:bg-surface-base-hover/70 transition-all text-left no-underline"
                title={item.url}
              >
                <div class="flex items-center justify-center size-5 rounded bg-surface-base/80 text-text-tertiary shrink-0 mt-0.5 group-hover:text-text-primary transition-colors">
                  <Show
                    when={item.isCode}
                    fallback={
                      <Show when={item.isDoc} fallback={<Icon name="globe" class="size-3" />}>
                        <Icon name="open-file" class="size-3" />
                      </Show>
                    }
                  >
                    <Icon name="code-lines" class="size-3" />
                  </Show>
                </div>
                <div class="flex flex-col min-w-0 flex-1">
                  <div class="flex items-center gap-1.5 justify-between">
                    <span class="text-[10px] font-mono uppercase tracking-wider text-text-tertiary px-1 py-0.2 rounded bg-surface-base/60 truncate">
                      {item.host}
                    </span>
                    <Icon name="square-arrow-top-right" class="size-3 text-text-tertiary opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                  </div>
                  <span class="text-xs font-medium text-text-primary group-hover:text-accent truncate mt-1">
                    {item.title}
                  </span>
                  <span class="text-[11px] font-mono text-text-tertiary truncate opacity-70">
                    {item.url}
                  </span>
                </div>
              </a>
            )}
          </For>
        </div>

        {/* Show more toggle */}
        <Show when={links().length > initialLimit}>
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              setShowAll(!showAll())
            }}
            class="self-center mt-1 px-3 py-1 text-xs font-medium rounded-md border border-border-weaker-base text-text-secondary hover:text-text-primary hover:bg-surface-base-hover transition-colors cursor-pointer"
          >
            {showAll() ? "Mostrar menos" : `+ Mostrar ${links().length - initialLimit} fuentes más`}
          </button>
        </Show>
      </div>
    </Show>
  )
}

function ToolFileAccordion(props: { path: string; actions?: JSX.Element; children: JSX.Element }) {
  const value = createMemo(() => props.path || "tool-file")

  return (
    <Accordion
      multiple
      data-scope="apply-patch"
      style={{ "--sticky-accordion-offset": "calc(32px + var(--tool-content-gap))" }}
      defaultValue={[value()]}
    >
      <Accordion.Item value={value()}>
        <StickyAccordionHeader>
          <Accordion.Trigger>
            <div data-slot="apply-patch-trigger-content">
              <div data-slot="apply-patch-file-info">
                <FileIcon node={{ path: props.path, type: "file" }} />
                <div data-slot="apply-patch-file-name-container">
                  <Show when={props.path.includes("/")}>
                    <span data-slot="apply-patch-directory">{`\u202A${getDirectory(props.path)}\u202C`}</span>
                  </Show>
                  <span data-slot="apply-patch-filename">{getFilename(props.path)}</span>
                </div>
              </div>
              <div data-slot="apply-patch-trigger-actions">
                {props.actions}
                <Icon name="chevron-grabber-vertical" size="small" />
              </div>
            </div>
          </Accordion.Trigger>
        </StickyAccordionHeader>
        <Accordion.Content>{props.children}</Accordion.Content>
      </Accordion.Item>
    </Accordion>
  )
}

ToolRegistry.register({
  name: "read",
  render(props) {
    const data = useData()
    const i18n = useI18n()
    const args: string[] = []
    if (props.input.offset) args.push("offset=" + props.input.offset)
    if (props.input.limit) args.push("limit=" + props.input.limit)
    const loaded = createMemo(() => {
      if (props.status !== "completed") return []
      const value = props.metadata.loaded
      if (!value || !Array.isArray(value)) return []
      return value.filter((p): p is string => typeof p === "string")
    })
    return (
      <>
        <BasicTool
          {...props}
          icon="glasses"
          variant="operation"
          trigger={{
            title: i18n.t("ui.tool.read"),
            subtitle: props.input.filePath ? getFilename(props.input.filePath) : "",
            args,
          }}
        />
        <For each={loaded()}>
          {(filepath) => (
            <div data-component="tool-loaded-file">
              <Icon name="enter" size="small" />
              <span>
                {i18n.t("ui.tool.loaded")} {relativizeProjectPath(filepath, data.directory)}
              </span>
            </div>
          )}
        </For>
      </>
    )
  },
})

ToolRegistry.register({
  name: "list",
  render(props) {
    const i18n = useI18n()
    return (
      <BasicTool
        {...props}
        icon="bullet-list"
        variant="operation"
        trigger={{ title: i18n.t("ui.tool.list"), subtitle: getDirectory(props.input.path || "/") }}
      >
        <Show when={props.output}>
          <div data-component="tool-output" data-scrollable>
            <Markdown text={props.output!} />
          </div>
        </Show>
      </BasicTool>
    )
  },
})

ToolRegistry.register({
  name: "glob",
  render(props) {
    const i18n = useI18n()
    return (
      <BasicTool
        {...props}
        icon="magnifying-glass"
        variant="operation"
        trigger={{
          title: i18n.t("ui.tool.glob"),
          subtitle: getDirectory(props.input.path || "/"),
          args: props.input.pattern ? ["pattern=" + props.input.pattern] : [],
        }}
      >
        <Show when={props.output}>
          <div data-component="tool-output" data-scrollable>
            <Markdown text={props.output!} />
          </div>
        </Show>
      </BasicTool>
    )
  },
})

ToolRegistry.register({
  name: "grep",
  render(props) {
    const i18n = useI18n()
    const args: string[] = []
    if (props.input.pattern) args.push("pattern=" + props.input.pattern)
    if (props.input.include) args.push("include=" + props.input.include)
    return (
      <BasicTool
        {...props}
        icon="magnifying-glass"
        variant="operation"
        trigger={{
          title: i18n.t("ui.tool.grep"),
          subtitle: getDirectory(props.input.path || "/"),
          args,
        }}
      >
        <Show when={props.output}>
          <div data-component="tool-output" data-scrollable>
            <Markdown text={props.output!} />
          </div>
        </Show>
      </BasicTool>
    )
  },
})

ToolRegistry.register({
  name: "webfetch",
  render(props) {
    const i18n = useI18n()
    const url = createMemo(() => {
      const value = props.input.url
      return typeof value === "string" ? value : ""
    })
    const openInNewTab: JSX.EventHandlerUnion<HTMLElement, MouseEvent> = (event) => {
      if (!url()) return
      if (event.button !== 0 || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return
      event.preventDefault()
      window.open(url(), "_blank", "noopener,noreferrer")
    }
    return (
      <BasicTool
        {...props}
        hideDetails
        icon="globe"
        variant="web"
        triggerHref={url() || undefined}
        clickable={!!url()}
        onTriggerClick={openInNewTab}
        trigger={{
          title: i18n.t("ui.tool.webfetch"),
          subtitle: url(),
          action: (
            <Show when={!!url()}>
              <Icon name="chevron-right" size="small" class="text-text-primary" />
            </Show>
          ),
        }}
      />
    )
  },
})

ToolRegistry.register({
  name: "websearch",
  render(props) {
    const query = createMemo(() => {
      const value = props.input.query
      if (typeof value !== "string") return ""
      return value
    })
    const title = createMemo(() => webSearchProviderLabel(props.metadata.provider))

    return (
      <BasicTool
        {...props}
        icon="window-cursor"
        variant="web"
        trigger={{
          title: title(),
          subtitle: query(),
          subtitleClass: "exa-tool-query",
        }}
      >
        <ExaOutput output={props.output} />
      </BasicTool>
    )
  },
})

ToolRegistry.register({
  name: "task",
  render(props) {
    const data = useData()
    const i18n = useI18n()
    const location = useLocation()
    const childSessionId = createMemo(() => {
      const value = props.metadata.sessionId
      if (typeof value === "string" && value) return value
      return taskSession(props.input, location.pathname, data.store.session, data.store.agent)
    })
    const agent = createMemo(() => taskAgent(props.input.subagent_type, data.store.agent))
    const title = createMemo(() => agent().name ?? i18n.t("ui.tool.agent.default"))
    const subtitle = createMemo(() => {
      const value =
        typeof props.input.description === "string" && props.input.description
          ? props.input.description
          : childSessionId()
      if (!value) return value
      if (props.metadata.background === true) return `${value} (background)`
      return value
    })
    const href = createMemo(() => sessionLink(childSessionId(), location.pathname, data.sessionHref))
    const clickable = createMemo(() => !!(childSessionId() && (data.navigateToSession || href())))

    const navigate = (event: MouseEvent) => {
      if (!data.navigateToSession) return
      if (event.button !== 0 || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return
      const id = childSessionId()
      if (!id) return
      event.preventDefault()
      data.navigateToSession(id)
    }

    return (
      <BasicTool
        {...props}
        icon="task"
        variant="agent"
        hideDetails
        triggerHref={href()}
        clickable={clickable()}
        onTriggerClick={navigate}
        trigger={{
          title: title(),
          subtitle: subtitle(),
          action: (
            <Show when={clickable()}>
              <Icon name="chevron-right" size="small" class="text-text-primary" />
            </Show>
          ),
        }}
      />
    )
  },
})

ToolRegistry.register({
  name: "bash",
  render(props) {
    const i18n = useI18n()
    const text = createMemo(() => {
      const cmd = props.input.command ?? props.metadata.command ?? ""
      const out = stripAnsi(props.output || props.metadata.output || "").replace(/\r\n?/g, "\n")
      return `$ ${cmd}${out ? "\n\n" + out : ""}`
    })
    const { copied, copy: copyToClipboard } = useCopyToClipboard()

    const handleCopy = async () => {
      const content = text()
      if (!content) return
      await copyToClipboard(content)
    }

    return (
      <BasicTool
        {...props}
        icon="console"
        variant="command"
        trigger={{
          title: i18n.t("ui.tool.shell"),
          subtitle: typeof props.input.description === "string" ? props.input.description : undefined,
        }}
      >
        <div data-component="bash-output">
          <div data-slot="bash-copy">
            <Tooltip
              value={copied() ? i18n.t("ui.message.copied") : i18n.t("ui.message.copy")}
              placement="top"
              gutter={4}
            >
              <IconButton
                icon={copied() ? "check" : "copy"}
                size="small"
                variant="ghost"
                onMouseDown={(e) => e.preventDefault()}
                onClick={handleCopy}
                aria-label={copied() ? i18n.t("ui.message.copied") : i18n.t("ui.message.copy")}
              />
            </Tooltip>
          </div>
          <div data-slot="bash-scroll" data-scrollable>
            <pre data-slot="bash-pre">
              <code>{text()}</code>
            </pre>
          </div>
        </div>
      </BasicTool>
    )
  },
})

ToolRegistry.register({
  name: "edit",
  render(props) {
    const i18n = useI18n()
    const fileComponent = useFileComponent()
    const diagnostics = createMemo(() => getDiagnostics(props.metadata.diagnostics, props.input.filePath))
    const path = createMemo(() => props.metadata?.filediff?.file || props.input.filePath || "")
    const filename = () => getFilename(props.input.filePath ?? "")
    const pending = () => props.status === "pending" || props.status === "running"
    const diffSource = createMemo(
      () => {
        const filediff = props.metadata?.filediff
        if (!filediff) return
        return {
          file: filediff.file || props.input.filePath || "",
          patch: typeof filediff.patch === "string" ? filediff.patch : undefined,
          before: typeof filediff.before === "string" ? filediff.before : undefined,
          after: typeof filediff.after === "string" ? filediff.after : undefined,
        }
      },
      undefined,
      {
        equals: (a, b) =>
          a?.file === b?.file && a?.patch === b?.patch && a?.before === b?.before && a?.after === b?.after,
      },
    )

    const fileCompProps = createMemo(() => {
      try {
        const source = diffSource()
        if (source) {
          const fileDiff = resolveFileDiff(source)
          if (fileDiff) return { fileDiff, hunkSeparators: fileDiff.isPartial ? "simple" : "line-info-basic" }
        }
      } catch (err) {
        console.warn("message-part: failed to resolve file diff, falling back to raw before/after", err)
      }

      return {
        before: {
          name: props.metadata?.filediff?.file || props.input.filePath,
          contents: props.metadata?.filediff?.before || props.input.oldString || "",
        },
        after: {
          name: props.metadata?.filediff?.file || props.input.filePath,
          contents: props.metadata?.filediff?.after || props.input.newString || "",
        },
      }
    })

    return (
      <div data-component="edit-tool">
        <BasicTool
          {...props}
          icon="code-lines"
          variant="operation"
          defer={props.deferContent !== false}
          trigger={
            <div data-component="edit-trigger">
              <div data-slot="message-part-title-area">
                <div data-slot="message-part-title">
                  <span data-slot="message-part-title-text">
                    <TextShimmer text={i18n.t("ui.messagePart.title.edit")} active={pending()} />
                  </span>
                  <Show when={!pending()}>
                    <span data-slot="message-part-title-filename">{filename()}</span>
                  </Show>
                </div>
                <Show when={!pending() && props.input.filePath?.includes("/")}>
                  <div data-slot="message-part-path">
                    <span data-slot="message-part-directory">{getDirectory(props.input.filePath)}</span>
                  </div>
                </Show>
              </div>
              <div data-slot="message-part-actions">
                <Show when={!pending() && props.metadata.filediff}>
                  <DiffChanges changes={props.metadata.filediff} />
                </Show>
              </div>
            </div>
          }
        >
          <Show when={path()}>
            <ToolFileAccordion
              path={path()}
              actions={
                <Show when={!pending() && props.metadata.filediff}>
                  <DiffChanges changes={props.metadata.filediff} />
                </Show>
              }
            >
              <div data-component="edit-content">
                <Dynamic component={fileComponent} mode="diff" virtualize={props.virtualizeDiff} {...fileCompProps()} />
              </div>
            </ToolFileAccordion>
          </Show>
          <DiagnosticsDisplay diagnostics={diagnostics()} />
        </BasicTool>
      </div>
    )
  },
})

ToolRegistry.register({
  name: "write",
  render(props) {
    const i18n = useI18n()
    const fileComponent = useFileComponent()
    const diagnostics = createMemo(() => getDiagnostics(props.metadata.diagnostics, props.input.filePath))
    const path = createMemo(() => props.input.filePath || "")
    const filename = () => getFilename(props.input.filePath ?? "")
    const pending = () => props.status === "pending" || props.status === "running"
    return (
      <div data-component="write-tool">
        <BasicTool
          {...props}
          icon="code-lines"
          variant="operation"
          defer={props.deferContent !== false}
          trigger={
            <div data-component="write-trigger">
              <div data-slot="message-part-title-area">
                <div data-slot="message-part-title">
                  <span data-slot="message-part-title-text">
                    <TextShimmer text={i18n.t("ui.messagePart.title.write")} active={pending()} />
                  </span>
                  <Show when={!pending()}>
                    <span data-slot="message-part-title-filename">{filename()}</span>
                  </Show>
                </div>
                <Show when={!pending() && props.input.filePath?.includes("/")}>
                  <div data-slot="message-part-path">
                    <span data-slot="message-part-directory">{getDirectory(props.input.filePath)}</span>
                  </div>
                </Show>
              </div>
              <div data-slot="message-part-actions">{/* <DiffChanges diff={diff} /> */}</div>
            </div>
          }
        >
          <Show when={props.input.content && path()}>
            <div data-component="write-content">
              <Dynamic
                component={fileComponent}
                mode="text"
                file={{
                  name: props.input.filePath,
                  contents: props.input.content,
                  cacheKey: checksum(props.input.content),
                }}
                overflow="scroll"
              />
            </div>
          </Show>
          <DiagnosticsDisplay diagnostics={diagnostics()} />
        </BasicTool>
      </div>
    )
  },
})

ToolRegistry.register({
  name: "apply_patch",
  render(props) {
    const i18n = useI18n()
    const fileComponent = useFileComponent()
    const files = createMemo(() => patchFiles(props.metadata.files))
    const pending = createMemo(() => props.status === "pending" || props.status === "running")
    const single = createMemo(() => {
      const list = files()
      if (list.length !== 1) return
      return list[0]
    })
    const [expanded, setExpanded] = createSignal<string[]>([])
    let seeded = false

    createEffect(() => {
      const list = files()
      if (list.length === 0) return
      if (seeded) return
      seeded = true
      setExpanded(list.filter((f) => f.type !== "delete").map((f) => f.filePath))
    })

    const subtitle = createMemo(() => {
      const count = files().length
      if (count === 0) return ""
      return `${count} ${i18n.t(count > 1 ? "ui.common.file.other" : "ui.common.file.one")}`
    })

    return (
      <Show
        when={single()}
        fallback={
          <div data-component="apply-patch-tool">
            <BasicTool
              {...props}
              icon="code-lines"
              variant="operation"
              defer={props.deferContent !== false}
              trigger={{
                title: i18n.t("ui.tool.patch"),
                subtitle: subtitle(),
              }}
            >
              <Show when={files().length > 0}>
                <Accordion
                  multiple
                  data-scope="apply-patch"
                  style={{ "--sticky-accordion-offset": "calc(32px + var(--tool-content-gap))" }}
                  value={expanded()}
                  onChange={(value) => setExpanded(Array.isArray(value) ? value : value ? [value] : [])}
                >
                  <For each={files()}>
                    {(file) => {
                      const active = createMemo(() => expanded().includes(file.filePath))
                      const [visible, setVisible] = createSignal(false)

                      createEffect(() => {
                        if (!active()) {
                          setVisible(false)
                          return
                        }

                        requestAnimationFrame(() => {
                          if (!active()) return
                          setVisible(true)
                        })
                      })

                      return (
                        <Accordion.Item value={file.filePath} data-type={file.type}>
                          <StickyAccordionHeader>
                            <Accordion.Trigger>
                              <div data-slot="apply-patch-trigger-content">
                                <div data-slot="apply-patch-file-info">
                                  <FileIcon node={{ path: file.relativePath, type: "file" }} />
                                  <div data-slot="apply-patch-file-name-container">
                                    <Show when={file.relativePath.includes("/")}>
                                      <span data-slot="apply-patch-directory">{`\u202A${getDirectory(file.relativePath)}\u202C`}</span>
                                    </Show>
                                    <span data-slot="apply-patch-filename">{getFilename(file.relativePath)}</span>
                                  </div>
                                </div>
                                <div data-slot="apply-patch-trigger-actions">
                                  <Switch>
                                    <Match when={file.type === "add"}>
                                      <span data-slot="apply-patch-change" data-type="added">
                                        {i18n.t("ui.patch.action.created")}
                                      </span>
                                    </Match>
                                    <Match when={file.type === "delete"}>
                                      <span data-slot="apply-patch-change" data-type="removed">
                                        {i18n.t("ui.patch.action.deleted")}
                                      </span>
                                    </Match>
                                    <Match when={file.type === "move"}>
                                      <span data-slot="apply-patch-change" data-type="modified">
                                        {i18n.t("ui.patch.action.moved")}
                                      </span>
                                    </Match>
                                    <Match when={true}>
                                      <DiffChanges changes={{ additions: file.additions, deletions: file.deletions }} />
                                    </Match>
                                  </Switch>
                                  <Icon name="chevron-grabber-vertical" size="small" />
                                </div>
                              </div>
                            </Accordion.Trigger>
                          </StickyAccordionHeader>
                          <Accordion.Content>
                            <Show when={props.deferContent === false || visible()}>
                              <div data-component="apply-patch-file-diff">
                                <Dynamic
                                  component={fileComponent}
                                  mode="diff"
                                  virtualize={props.virtualizeDiff}
                                  fileDiff={file.view.fileDiff}
                                  hunkSeparators={file.view.fileDiff.isPartial ? "simple" : "line-info-basic"}
                                />
                              </div>
                            </Show>
                          </Accordion.Content>
                        </Accordion.Item>
                      )
                    }}
                  </For>
                </Accordion>
              </Show>
            </BasicTool>
          </div>
        }
      >
        <div data-component="apply-patch-tool">
          <BasicTool
            {...props}
            icon="code-lines"
            variant="operation"
            defer={props.deferContent !== false}
            trigger={
              <div data-component="edit-trigger">
                <div data-slot="message-part-title-area">
                  <div data-slot="message-part-title">
                    <span data-slot="message-part-title-text">
                      <TextShimmer text={i18n.t("ui.tool.patch")} active={pending()} />
                    </span>
                    <Show when={!pending()}>
                      <span data-slot="message-part-title-filename">{getFilename(single()!.relativePath)}</span>
                    </Show>
                  </div>
                  <Show when={!pending() && single()!.relativePath.includes("/")}>
                    <div data-slot="message-part-path">
                      <span data-slot="message-part-directory">{getDirectory(single()!.relativePath)}</span>
                    </div>
                  </Show>
                </div>
                <div data-slot="message-part-actions">
                  <Show when={!pending()}>
                    <DiffChanges changes={{ additions: single()!.additions, deletions: single()!.deletions }} />
                  </Show>
                </div>
              </div>
            }
          >
            <ToolFileAccordion
              path={single()!.relativePath}
              actions={
                <Switch>
                  <Match when={single()!.type === "add"}>
                    <span data-slot="apply-patch-change" data-type="added">
                      {i18n.t("ui.patch.action.created")}
                    </span>
                  </Match>
                  <Match when={single()!.type === "delete"}>
                    <span data-slot="apply-patch-change" data-type="removed">
                      {i18n.t("ui.patch.action.deleted")}
                    </span>
                  </Match>
                  <Match when={single()!.type === "move"}>
                    <span data-slot="apply-patch-change" data-type="modified">
                      {i18n.t("ui.patch.action.moved")}
                    </span>
                  </Match>
                  <Match when={true}>
                    <DiffChanges changes={{ additions: single()!.additions, deletions: single()!.deletions }} />
                  </Match>
                </Switch>
              }
            >
              <div data-component="apply-patch-file-diff">
                <Dynamic
                  component={fileComponent}
                  mode="diff"
                  virtualize={props.virtualizeDiff}
                  fileDiff={single()!.view.fileDiff}
                />
              </div>
            </ToolFileAccordion>
          </BasicTool>
        </div>
      </Show>
    )
  },
})

ToolRegistry.register({
  name: "todowrite",
  render(props) {
    const i18n = useI18n()
    const todos = createMemo(() => {
      const meta = props.metadata?.todos
      if (Array.isArray(meta)) return meta

      const input = props.input.todos
      if (Array.isArray(input)) return input

      return []
    })

    const subtitle = createMemo(() => {
      const list = todos()
      if (list.length === 0) return ""
      return `${list.filter((t: Todo) => t.status === "completed").length}/${list.length}`
    })

    return (
      <BasicTool
        {...props}
        defaultOpen
        icon="checklist"
        variant="system"
        trigger={{
          title: i18n.t("ui.tool.todos"),
          subtitle: subtitle(),
        }}
      >
        <Show when={todos().length}>
          <div data-component="todos">
            <For each={todos()}>
              {(todo: Todo) => (
                <Checkbox readOnly checked={todo.status === "completed"}>
                  <span
                    data-slot="message-part-todo-content"
                    data-completed={todo.status === "completed" ? "completed" : undefined}
                  >
                    {todo.content}
                  </span>
                </Checkbox>
              )}
            </For>
          </div>
        </Show>
      </BasicTool>
    )
  },
})

ToolRegistry.register({
  name: "question",
  render(props) {
    const i18n = useI18n()
    const questions = createMemo(() => (props.input.questions ?? []) as QuestionInfo[])
    const answers = createMemo(() => (props.metadata.answers ?? []) as QuestionAnswer[])
    const completed = createMemo(() => answers().length > 0)

    const subtitle = createMemo(() => {
      const count = questions().length
      if (count === 0) return ""
      if (completed()) return i18n.t("ui.question.subtitle.answered", { count })
      return `${count} ${i18n.t(count > 1 ? "ui.common.question.other" : "ui.common.question.one")}`
    })

    return (
      <BasicTool
        {...props}
        defaultOpen={completed()}
        icon="help-circle"
        variant="question"
        trigger={{
          title: i18n.t("ui.tool.questions"),
          subtitle: subtitle(),
        }}
      >
        <Show when={completed()}>
          <div data-component="question-answers" class="flex flex-col gap-2.5 p-3.5 border-t border-border-weaker-base bg-bg-surface">
            <For each={questions()}>
              {(q, i) => {
                const answer = () => answers()[i()] ?? []
                const answerStr = () => answer().join(", ") || i18n.t("ui.question.answer.none")
                return (
                  <div data-slot="question-answer-item" class="flex flex-col gap-2 p-3 rounded-lg border border-border-weaker-base bg-bg-elevated/40">
                    <div data-slot="question-text" class="flex items-start gap-2.5 text-13-medium text-text-primary">
                      <Icon name="help-circle" class="size-4 shrink-0 text-text-secondary mt-0.5" />
                      <span class="leading-snug">{q.question}</span>
                    </div>
                    <div data-slot="answer-text" class="flex items-center gap-2 pl-6 text-12-medium text-state-fg-success">
                      <Icon name="check-small" class="size-4 shrink-0 text-state-fg-success" />
                      <span class="font-medium">{answerStr()}</span>
                    </div>
                  </div>
                )
              }}
            </For>
          </div>
        </Show>
      </BasicTool>
    )
  },
})

ToolRegistry.register({
  name: "skill",
  render(props) {
    const i18n = useI18n()
    const title = createMemo(() => props.input.name || i18n.t("ui.tool.skill"))

    return (
      <BasicTool
        {...props}
        icon="brain"
        variant="agent"
        hideDetails
        trigger={{ title: title(), titleClass: "capitalize" }}
      />
    )
  },
})


