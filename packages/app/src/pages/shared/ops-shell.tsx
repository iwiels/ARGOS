import { createEffect, onCleanup, type JSX, type ParentProps } from "solid-js"
import { Icon } from "@argos/ui/icon"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { EmptyState } from "@/components/audit-ui"
import { useSDK } from "@/context/sdk"

const REFRESH_EVENT_TYPES: ReadonlySet<string> = new Set([
  "session.created",
  "session.updated",
  "session.deleted",
  "session.idle",
  "session.status",
  "session.error",
  "message.updated",
  "message.removed",
  "message.part.updated",
  "message.part.removed",
  "session.next.step.started",
  "session.next.step.ended",
  "session.next.step.failed",
  "session.next.tool.called",
  "session.next.tool.success",
  "session.next.tool.failed",
  "file.edited",
])

export function OpsRefreshButton(props: {
  label: string
  onClick: () => void
  class?: string
  disabled?: boolean
  iconClass?: string
}) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      disabled={props.disabled}
      class={
        props.class ??
        "inline-flex items-center gap-1.5 rounded-md border border-border-weaker-base bg-bg-surface px-3 py-1.5 text-xs font-medium text-text-primary hover:bg-bg-elevated transition-colors"
      }
    >
      <Icon name="refresh" size="small" class={props.iconClass} />
      {props.label}
    </button>
  )
}

export function OpsErrorPanel(props: { title: string; body: string; retryLabel: string; onRetry: () => void }) {
  return (
    <EmptyState
      tone="danger"
      icon={<PixelIcon name="warning" size={40} />}
      title={props.title}
      description={props.body}
    >
      <button
        type="button"
        onClick={props.onRetry}
        class="mt-1 inline-flex items-center gap-1.5 rounded-md border border-border-weaker-base bg-bg-surface px-3 py-1.5 text-xs font-medium text-text-primary hover:bg-bg-elevated transition-colors"
      >
        <Icon name="refresh" size="small" />
        {props.retryLabel}
      </button>
    </EmptyState>
  )
}

export function OpsCard(
  props: ParentProps<{
    headerClass: string
    contentClass: string
    class?: string
    title?: JSX.Element
    trailing?: JSX.Element
  }>,
) {
  return (
    <div class={`rounded-lg border border-border-weaker-base bg-bg-surface ${props.class ?? ""}`}>
      <div class={props.headerClass}>
        {props.title}
        {props.trailing}
      </div>
      <div class={props.contentClass}>{props.children}</div>
    </div>
  )
}

export function useAutoRefresh(refresh: () => void, debounceMs = 500) {
  const sdk = useSDK()
  let pending = false
  let timer: ReturnType<typeof setTimeout> | undefined

  const flush = () => {
    if (timer !== undefined) return
    timer = setTimeout(() => {
      timer = undefined
      if (!pending) return
      pending = false
      refresh()
    }, debounceMs)
  }

  const schedule = () => {
    pending = true
    if (typeof document !== "undefined" && document.hidden) return
    flush()
  }

  createEffect(() => {
    const unsub = sdk.event.listen((evt) => {
      if (!REFRESH_EVENT_TYPES.has(evt.details.type)) return
      schedule()
    })
    const onVisibility = () => {
      if (document.hidden || !pending) return
      if (timer !== undefined) {
        clearTimeout(timer)
        timer = undefined
      }
      pending = false
      refresh()
    }
    document.addEventListener("visibilitychange", onVisibility)
    onCleanup(() => {
      unsub()
      document.removeEventListener("visibilitychange", onVisibility)
      if (timer !== undefined) clearTimeout(timer)
    })
  })
}
