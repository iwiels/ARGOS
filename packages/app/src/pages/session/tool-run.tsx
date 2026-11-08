import { createMemo, createSignal, For, Show, type JSX } from "solid-js"
import { Collapsible } from "@argos/ui/collapsible"
import { Icon } from "@argos/ui/icon"
import { Spinner } from "@argos/ui/spinner"
import { TextShimmer } from "@argos/ui/text-shimmer"
import { getToolInfo } from "@argos/ui/message-part"
import type { AssistantMessage, ToolPart } from "@argos/sdk/client"

export type ToolRunItem = {
  part: ToolPart
  message?: AssistantMessage
}

function runSubtitle(part: ToolPart): string | undefined {
  const input = part.state.input
  if (!input || typeof input !== "object") return undefined
  const keys = ["command", "description", "query", "url", "filePath", "path", "pattern", "name"]
  for (const key of keys) {
    const value = (input as Record<string, unknown>)[key]
    if (typeof value === "string" && value.trim()) {
      const clean = value.replace(/[\r\n]+/g, " ").trim()
      return clean.length > 70 ? `${clean.slice(0, 70)}…` : clean
    }
  }
  return undefined
}

function partStatus(part: ToolPart): "pending" | "running" | "done" | "error" {
  const status = part.state.status
  if (status === "pending" || status === "running") return status
  if (status === "error") return "error"
  return "done"
}

export function ToolRunGroup(props: {
  tool: string
  items: ToolRunItem[]
  renderPart: (item: ToolRunItem) => JSX.Element
  onSizeChange?: () => void
}) {
  const [open, setOpen] = createSignal(false)

  const last = createMemo(() => props.items[props.items.length - 1])
  const info = createMemo(() => {
    const item = last()
    const input = item?.part.state.input
    const metadata = item && "metadata" in item.part.state ? item.part.state.metadata : undefined
    return getToolInfo(props.tool, input, metadata as Record<string, unknown> | undefined)
  })
  const subtitle = createMemo(() => {
    const fallback = info().subtitle
    const item = last()
    if (!item) return fallback
    return runSubtitle(item.part) ?? fallback
  })
  const running = createMemo(() =>
    props.items.some((item) => partStatus(item.part) === "running" || partStatus(item.part) === "pending"),
  )
  const failed = createMemo(() => props.items.some((item) => partStatus(item.part) === "error"))
  const status = createMemo<"running" | "error" | "done">(() => {
    if (running()) return "running"
    if (failed()) return "error"
    return "done"
  })

  const handleOpenChange = (value: boolean) => {
    setOpen(value)
    props.onSizeChange?.()
  }

  return (
    <Collapsible
      open={open()}
      onOpenChange={handleOpenChange}
      class="tool-run"
      data-component="tool-run"
      data-timeline-part-ids={props.items.map((item) => item.part.id).join(",")}
    >
      <Collapsible.Trigger>
        <div data-slot="tool-run-trigger">
          <Icon name={info().icon} class="shrink-0" />
          <span data-slot="tool-run-title">
            <TextShimmer text={info().title} active={running()} />
          </span>
          <Show when={props.items.length > 1}>
            <span data-slot="tool-run-count">×{props.items.length}</span>
          </Show>
          <Show when={subtitle()}>
            <span data-slot="tool-run-subtitle">{subtitle()}</span>
          </Show>
          <div data-slot="tool-run-status" aria-hidden="true">
            <Show when={status() === "running"}>
              <Spinner class="size-3.5" />
            </Show>
          </div>
          <Collapsible.Arrow />
        </div>
      </Collapsible.Trigger>
      <Collapsible.Content>
        <div data-slot="tool-run-list" class="flex flex-col border-t border-border-weaker-base bg-bg-surface">
          <For each={props.items}>
            {(item) => (
              <div data-slot="tool-run-item" class="w-full border-b border-border-weaker-base/60 last:border-b-0">
                <div data-slot="tool-run-item-content" class="w-full">{props.renderPart(item)}</div>
              </div>
            )}
          </For>
        </div>
      </Collapsible.Content>
    </Collapsible>
  )
}
