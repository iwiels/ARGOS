import { createEffect, createMemo, For, Match, on, onCleanup, onMount, Show, Switch, type JSX } from "solid-js"
import { animate, type AnimationPlaybackControls } from "motion"
import { useI18n } from "../context/i18n"
import { createStore } from "solid-js/store"
import { Collapsible } from "./collapsible"
import { Icon, type IconProps } from "./icon"
import { TextShimmer } from "./text-shimmer"

export type TriggerTitle = {
  title: string
  titleClass?: string
  subtitle?: string
  subtitleClass?: string
  args?: string[]
  argsClass?: string
  action?: JSX.Element
}

export type ToolVisualVariant = "operation" | "command" | "question" | "web" | "memory" | "agent" | "security" | "system"

const isTriggerTitle = (val: any): val is TriggerTitle => {
  return (
    typeof val === "object" && val !== null && "title" in val && (typeof Node === "undefined" || !(val instanceof Node))
  )
}

export interface BasicToolProps {
  icon: IconProps["name"]
  trigger: TriggerTitle | JSX.Element
  variant?: ToolVisualVariant
  children?: JSX.Element
  status?: string
  hideDetails?: boolean
  defaultOpen?: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
  forceOpen?: boolean
  defer?: boolean
  locked?: boolean
  animated?: boolean
  onSubtitleClick?: () => void
  onTriggerClick?: JSX.EventHandlerUnion<HTMLElement, MouseEvent>
  triggerHref?: string
  clickable?: boolean
}

const SPRING = { type: "spring" as const, visualDuration: 0.35, bounce: 0 }
const deferredMounts: Array<{ active: boolean; fn: () => void }> = []
let deferredFrame: number | undefined

function flushDeferredMounts() {
  while (deferredMounts.length > 0) {
    // Timeline tools are mounted top-to-bottom, but the viewport starts at the latest turn.
    // Pop from the end so heavy default-open bodies near the bottom become interactive first.
    const item = deferredMounts.pop()!
    if (item.active) {
      deferredFrame = deferredMounts.length > 0 ? requestAnimationFrame(flushDeferredMounts) : undefined
      item.fn()
      return
    }
  }
  deferredFrame = undefined
}

function scheduleDeferredFlush() {
  if (deferredFrame !== undefined) return
  deferredFrame = requestAnimationFrame(() => {
    deferredFrame = requestAnimationFrame(flushDeferredMounts)
  })
}

function scheduleDeferredMount(fn: () => void) {
  const item = { active: true, fn }
  deferredMounts.push(item)
  scheduleDeferredFlush()
  return () => {
    item.active = false
  }
}

function scheduleFrameMount(fn: () => void) {
  const frame = requestAnimationFrame(fn)
  return () => cancelAnimationFrame(frame)
}

export function BasicTool(props: BasicToolProps) {
  const [state, setState] = createStore({
    open: props.defaultOpen ?? false,
    ready: !props.defer && (props.defaultOpen ?? false),
  })
  const open = () => props.open ?? state.open
  const ready = () => state.ready
  const pending = () => props.status === "pending" || props.status === "running"
  const hasChildren = () => (props.defer ? "children" in props : props.children)

  let cancelReady: (() => void) | undefined

  const cancel = () => {
    cancelReady?.()
    cancelReady = undefined
  }

  const scheduleReady = (initial = false) => {
    cancel()
    cancelReady = (initial ? scheduleDeferredMount : scheduleFrameMount)(() => {
      cancelReady = undefined
      if (!open()) return
      setState("ready", true)
    })
  }

  onCleanup(cancel)

  onMount(() => {
    if (props.defer && open()) scheduleReady(true)
  })

  const setOpen = (value: boolean) => {
    if (props.open === undefined) setState("open", value)
    props.onOpenChange?.(value)
  }

  createEffect(() => {
    if (!props.forceOpen) return
    if (open()) return
    setOpen(true)
  })

  createEffect(
    on(
      open,
      (value) => {
        if (!props.defer) return
        if (!value) {
          cancel()
          setState("ready", false)
          return
        }

        scheduleReady()
      },
      { defer: true },
    ),
  )

  // Animated height for collapsible open/close
  let contentRef: HTMLDivElement | undefined
  let heightAnim: AnimationPlaybackControls | undefined
  const initialOpen = open()

  createEffect(
    on(
      open,
      (isOpen) => {
        if (!props.animated || !contentRef) return
        heightAnim?.stop()
        if (isOpen) {
          contentRef.style.overflow = "hidden"
          heightAnim = animate(contentRef, { height: "auto" }, SPRING)
          void heightAnim.finished.then(() => {
            if (!contentRef || !open()) return
            contentRef.style.overflow = "visible"
            contentRef.style.height = "auto"
          })
        } else {
          contentRef.style.overflow = "hidden"
          heightAnim = animate(contentRef, { height: "0px" }, SPRING)
        }
      },
      { defer: true },
    ),
  )

  onCleanup(() => {
    heightAnim?.stop()
  })

  const handleOpenChange = (value: boolean) => {
    if (pending()) return
    if (props.locked && !value) return
    setOpen(value)
  }

  const triggerTitle = createMemo(() => (isTriggerTitle(props.trigger) ? props.trigger : undefined))

  const trigger = () => (
    <div
      data-slot="basic-tool-trigger"
      data-component="tool-trigger"
      data-clickable={props.clickable ? "true" : undefined}
      data-hide-details={props.hideDetails ? "true" : undefined}
      class="flex items-center gap-2 w-full min-w-0 h-full overflow-hidden"
    >
      <Icon name={props.icon} class="shrink-0 size-4" />
      <div data-slot="basic-tool-labels" class="min-w-0 flex-1 flex items-center gap-2 overflow-hidden">
        <Switch>
          <Match when={triggerTitle()}>
            {(title) => (
              <div data-slot="basic-tool-info-structured" class="flex items-center gap-2 min-w-0 max-w-full overflow-hidden flex-nowrap">
                <div data-slot="basic-tool-info-main" class="flex items-center gap-2 min-w-0 max-w-full overflow-hidden flex-nowrap">
                  <span
                    data-slot="basic-tool-title"
                    class="shrink-0 font-medium text-13"
                    classList={{
                      [title().titleClass ?? ""]: !!title().titleClass,
                    }}
                  >
                    <TextShimmer text={title().title} active={pending()} />
                  </span>
                  <Show when={!pending()}>
                    <Show when={title().subtitle}>
                      <span
                        data-slot="basic-tool-subtitle"
                        title={title().subtitle}
                        class="min-w-0 truncate text-13 font-normal"
                        classList={{
                          [title().subtitleClass ?? ""]: !!title().subtitleClass,
                          clickable: !!props.onSubtitleClick,
                        }}
                        onClick={(e) => {
                          if (props.onSubtitleClick) {
                            e.stopPropagation()
                            props.onSubtitleClick()
                          }
                        }}
                      >
                        {title().subtitle}
                      </span>
                    </Show>
                    <Show when={title().args?.length}>
                      <For each={title().args}>
                        {(arg) => (
                          <span
                            data-slot="basic-tool-arg"
                            title={arg}
                            class="min-w-0 truncate text-12 font-mono text-text-secondary shrink"
                            classList={{
                              [title().argsClass ?? ""]: !!title().argsClass,
                            }}
                          >
                            {arg}
                          </span>
                        )}
                      </For>
                    </Show>
                  </Show>
                </div>
              </div>
            )}
          </Match>
          <Match when={true}>{props.trigger as JSX.Element}</Match>
        </Switch>
      </div>
      <Show when={!pending() && triggerTitle()?.action}>
        {(action) => (
          <span data-slot="basic-tool-action" class="shrink-0 ml-auto flex items-center justify-center size-5 text-text-primary">
            {action()}
          </span>
        )}
      </Show>
      <Show when={hasChildren() && !props.hideDetails && !props.locked && !pending() && !triggerTitle()?.action}>
        <Collapsible.Arrow class="shrink-0 ml-auto" />
      </Show>
    </div>
  )

  return (
    <Collapsible
      open={open()}
      onOpenChange={handleOpenChange}
      class="group flex flex-col overflow-hidden rounded-lg transition-colors border border-border-weaker-base bg-bg-surface w-full min-w-0 max-w-full"
      data-component="basic-tool"
      data-variant={props.variant}
    >
      <Show
        when={props.triggerHref}
        fallback={
          <Show when={!props.hideDetails} fallback={
            <div
              data-slot="collapsible-trigger"
              data-hide-details="true"
              class="w-full flex items-center justify-between px-3 py-0 text-left h-9 min-h-[36px] max-h-[36px]"
              role={props.onTriggerClick ? "button" : undefined}
              tabIndex={props.onTriggerClick ? 0 : undefined}
              onClick={props.onTriggerClick}
              onKeyDown={(event) => {
                if (!props.onTriggerClick) return
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault()
                  const handler = props.onTriggerClick
                  if (typeof handler === "function") {
                    handler(event as unknown as Parameters<typeof handler>[0])
                  }
                }
              }}
            >
              {trigger()}
            </div>
          }>
            <Collapsible.Trigger onClick={props.onTriggerClick} class="w-full flex items-center justify-between px-3 py-0 text-left outline-none transition-colors hover:bg-surface-base-hover h-9 min-h-[36px] max-h-[36px]">
              {trigger()}
            </Collapsible.Trigger>
          </Show>
        }
      >
        {(href) => (
          <Collapsible.Trigger
            as="a"
            class="w-full flex items-center justify-between px-3 py-0 text-left outline-none transition-colors hover:bg-surface-base-hover h-9 min-h-[36px] max-h-[36px]"
            href={href()}
            data-hide-details={props.hideDetails ? "true" : undefined}
            onClick={props.onTriggerClick}
          >
            {trigger()}
          </Collapsible.Trigger>
        )}
      </Show>
      <Show when={props.animated && hasChildren() && !props.hideDetails}>
        <div
          ref={contentRef}
          data-slot="basic-tool-content"
          data-animated
          style={{
            height: initialOpen ? "auto" : "0px",
            overflow: initialOpen ? "visible" : "hidden",
          }}
        >
          <div data-slot="basic-tool-content-inner">
            <Show when={!props.defer || ready()}>{props.children}</Show>
          </div>
        </div>
      </Show>
      <Show when={!props.animated && hasChildren() && !props.hideDetails}>
        <Collapsible.Content data-slot="basic-tool-content">
          <div data-slot="basic-tool-content-inner">
            <Show when={!props.defer || ready()}>{props.children}</Show>
          </div>
        </Collapsible.Content>
      </Show>
    </Collapsible>
  )
}

function label(input: Record<string, unknown> | undefined) {
  const keys = ["description", "query", "url", "filePath", "path", "pattern", "name", "run_id", "command"]
  return keys.map((key) => input?.[key]).find((value): value is string => typeof value === "string" && value.length > 0)
}

function args(input: Record<string, unknown> | undefined) {
  if (!input) return []
  const skip = new Set(["description", "query", "url", "filePath", "path", "pattern", "name", "run_id", "command"])
  return Object.entries(input)
    .filter(([key]) => !skip.has(key))
    .flatMap(([key, value]) => {
      if (typeof value === "string") {
        const clean = value.replace(/[\r\n]+/g, " ").trim()
        const truncated = clean.length > 40 ? `${clean.slice(0, 40)}…` : clean
        return [`${key}=${truncated}`]
      }
      if (typeof value === "number") return [`${key}=${value}`]
      if (typeof value === "boolean") return [`${key}=${value}`]
      return []
    })
    .slice(0, 2)
}

function visualVariant(tool: string): ToolVisualVariant {
  const name = tool.toLowerCase()
  if (name === "question") return "question"
  if (name === "bash" || name === "shell") return "command"
  if (name === "task" || name === "skill") return "agent"
  if (name.includes("memory") || name.includes("finding")) return "memory"
  if (name.includes("audit") || name.includes("recon") || name.startsWith("argos"))
    return "security"
  if (name.includes("web") || name.includes("http") || name.includes("browser") || name.includes("chrome") || name.includes("devtools")) return "web"
  if (name.includes("script") || name.includes("exec")) return "command"
  if (["read", "list", "glob", "grep", "edit", "write", "apply_patch", "save"].includes(name)) return "operation"
  return "system"
}

export function GenericTool(props: {
  tool: string
  status?: string
  hideDetails?: boolean
  input?: Record<string, unknown>
  output?: string
}) {
  const i18n = useI18n()
  const inputContent = createMemo(() => {
    if (!props.input || Object.keys(props.input).length === 0) return undefined
    try {
      return JSON.stringify(props.input, null, 2)
    } catch {
      return String(props.input)
    }
  })

  return (
    <BasicTool
      icon="mcp"
      variant={visualVariant(props.tool)}
      status={props.status}
      trigger={{
        title: i18n.t("ui.basicTool.called", { tool: props.tool }),
        subtitle: label(props.input),
        args: args(props.input),
      }}
      hideDetails={props.hideDetails}
    >
      <Show when={inputContent() || props.output}>
        <div data-component="generic-tool-output" class="p-3 bg-bg-surface rounded-lg border border-border-weaker-base flex flex-col gap-2 font-mono text-12-regular text-text-primary overflow-x-auto max-h-96">
          <Show when={inputContent()}>
            <div class="text-[11px] font-semibold text-text-tertiary uppercase tracking-wider">Input</div>
            <pre class="whitespace-pre-wrap break-words">{inputContent()}</pre>
          </Show>
          <Show when={props.output}>
            <div class="text-[11px] font-semibold text-text-tertiary uppercase tracking-wider mt-2 border-t border-border-weaker-base pt-2">Output</div>
            <pre class="whitespace-pre-wrap break-words">{props.output}</pre>
          </Show>
        </div>
      </Show>
    </BasicTool>
  )
}

