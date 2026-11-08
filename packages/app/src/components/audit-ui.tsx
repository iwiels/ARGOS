import { Icon } from "@argos/ui/icon"
import { PixelIcon } from "@argos/ui/pixel-icon"
import { type ComponentProps, type JSX, type ParentProps } from "solid-js"

export function SurfaceCard(props: ParentProps<{ class?: string }>) {
  return <section class={`rounded-lg border border-border-weaker-base bg-bg-surface ${props.class ?? ""}`}>{props.children}</section>
}

export function PageHeader(props: {
  title: JSX.Element
  description?: JSX.Element
  actions?: JSX.Element
  class?: string
  variant?: "cockpit" | "dossier"
  size?: "sheet" | "hero"
  center?: boolean
}) {
  const dossier = () => props.variant === "dossier"
  const hero = () => props.size === "hero"
  return (
    <header
      class={
        dossier()
          ? `flex min-w-0 gap-4 ${props.center ? "items-center justify-center text-center" : "items-center justify-between"} ${props.class ?? ""}`
          : `flex shrink-0 items-center justify-between gap-4 border-b border-border-weaker-base px-6 py-4 ${props.class ?? ""}`
      }
    >
      <div class="min-w-0">
        <h1
          class={
            dossier()
              ? `font-display font-bold uppercase tracking-tight text-text-primary ${hero() ? "text-3xl sm:text-4xl leading-[0.9]" : "text-2xl leading-none"}`
              : "font-display text-xl font-bold uppercase leading-none tracking-tight text-text-primary"
          }
        >
          {props.title}
        </h1>
        {props.description ? (
          <p class={dossier() ? "mt-2 font-mono text-xs uppercase tracking-wider text-text-tertiary" : "mt-1.5 text-sm text-text-secondary"}>
            {props.description}
          </p>
        ) : null}
      </div>
      {props.actions ? <div class="flex shrink-0 items-center gap-2">{props.actions}</div> : null}
    </header>
  )
}
// EXCEPCIÓN DOCUMENTADA (V4): settings y diálogos quedan FUERA de PageHeader
// con titulaciones sentence-case heredadas (settings-list, dialog-*,
// error.tsx). Convergerlos a display/uppercase rompería su jerarquía
// heredada del upstream; solo las superficies cockpit (variant cockpit) y
// dossier editorial (variant dossier: home, audit-list, report-panel) usan
// PageHeader.

export function EmptyState(
  props: ParentProps<{
    icon: JSX.Element
    title: string
    description: string
    class?: string
    tone?: "neutral" | "danger"
  }>,
) {
  const danger = () => props.tone === "danger"
  return (
    <div class={`flex flex-1 flex-col items-center justify-center gap-4 p-8 text-center ${props.class ?? ""}`}>
      <div
        class={`mb-1 flex h-20 w-20 items-center justify-center rounded-[4px] border ${
          danger()
            ? "border-severity-border-critical bg-severity-bg-critical text-severity-fg-critical"
            : "border-border-weaker-base bg-bg-surface text-text-tertiary shadow-[1px_0_8px_rgba(0,0,0,0.25)]"
        }`}
      >
        {props.icon}
      </div>
      <div class="font-display text-base font-bold uppercase tracking-wide text-text-primary">{props.title}</div>
      <div class={`leading-relaxed text-text-secondary ${danger() ? "max-w-100 text-xs" : "max-w-md text-xs"}`}>{props.description}</div>
      {props.children}
    </div>
  )
}

export function KpiCard(props: {
  label: string
  value: number | string
  icon: string
  accent?: string
  trend?: JSX.Element
}) {
  return (
    <div class="flex flex-col gap-2 rounded-[4px] border border-border-weaker-base bg-bg-surface px-4 py-3.5 transition-colors hover:border-border-strong">
      <div class="flex items-start justify-between">
        <span class="text-xs font-medium uppercase tracking-wider text-text-secondary">{props.label}</span>
        <div
          class="flex h-8 w-8 shrink-0 items-center justify-center rounded-[4px] border border-border-weaker-base bg-bg-elevated text-text-secondary"
          style={props.accent ? { color: props.accent } : undefined}
        >
          <PixelIcon name={props.icon} size={20} />
        </div>
      </div>
      <span
        class="font-display text-2xl font-bold leading-none tabular-nums text-text-primary"
        style={props.accent ? { color: props.accent } : undefined}
      >
        {props.value}
      </span>
      {props.trend}
    </div>
  )
}

