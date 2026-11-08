import { type ComponentProps, type JSX, Show, splitProps } from "solid-js"
import type { ParentProps } from "solid-js"
import "./folder-tab.css"

export interface FolderTabProps extends ComponentProps<"div"> {
  label: string
  color?: string
  textColor?: string
  active?: boolean
  badge?: string | number
  icon?: JSX.Element
}

// REGLA DOSSIER (V3): FolderTab es la etiqueta dossier ESTÁTICA — el rótulo
// físico "EXPEDIENTE // ..." de home (scope-briefing), audit-list-view y
// report-panel. No es un tablist: no conmuta contenido ni lleva a11y de tabs.
// El tablist INTERACTIVO del dossier (review tabs de session-side-panel) es
// <Tabs variant="dossier"> (tabs.css). No borrar ninguno: conviven por rol
// distinto (etiqueta estática vs tablist interactivo).
export function FolderTab(props: FolderTabProps) {
  const [split, rest] = splitProps(props, [
    "label",
    "color",
    "textColor",
    "active",
    "badge",
    "icon",
    "class",
    "classList",
    "style",
  ])

  const color = () => split.color ?? "var(--accent)"
  const textColor = () => split.textColor ?? "var(--accent-fg, var(--black-900))"
  const isActive = () => split.active ?? false

  return (
    <div
      data-component="folder-tab"
      data-active={isActive() ? "true" : "false"}
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
      style={{
        "--tab-color": color(),
        "--tab-text": textColor(),
        ...(typeof split.style === "object" ? split.style : {}),
      }}
      {...rest}
    >
      {/* Ear Left (mirrored) */}
      <svg
        class="folder-tab-ear folder-tab-ear-start"
        viewBox="0 0 62 44"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <path
          d="M1.1449 0L-521.145 0C-531.065 0 -540.343 4.90374 -545.932 13.0999L-558.55 31.6066C-563.837 39.3607 -572.615 44 -582 44L62 44C52.6151 44 43.8369 39.3607 38.5499 31.6066L25.9318 13.0999C20.3434 4.90373 11.0649 0 1.1449 0Z"
          fill="currentColor"
        />
      </svg>

      {/* Ear Middle (Flexible width) */}
      <div class="folder-tab-middle">
        <Show when={split.icon}>
          <span class="inline-flex shrink-0">{split.icon}</span>
        </Show>
        <span>{split.label}</span>
        <Show when={split.badge !== undefined}>
          <span class="folder-tab-badge">{split.badge}</span>
        </Show>
      </div>

      {/* Ear Right */}
      <svg
        class="folder-tab-ear folder-tab-ear-end"
        viewBox="0 0 62 44"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <path
          d="M1.1449 0L-521.145 0C-531.065 0 -540.343 4.90374 -545.932 13.0999L-558.55 31.6066C-563.837 39.3607 -572.615 44 -582 44L62 44C52.6151 44 43.8369 39.3607 38.5499 31.6066L25.9318 13.0999C20.3434 4.90373 11.0649 0 1.1449 0Z"
          fill="currentColor"
        />
      </svg>
    </div>
  )
}

export function DossierFolder(props: ParentProps<{ class?: string; classList?: Record<string, boolean> }>) {
  const [split, rest] = splitProps(props, ["class", "classList"])
  return (
    <div
      data-component="dossier-folder"
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
      {...rest}
    >
      {props.children}
    </div>
  )
}

export function DossierFolderSheet(props: ParentProps<{ class?: string; classList?: Record<string, boolean> }>) {
  const [split, rest] = splitProps(props, ["class", "classList"])
  return (
    <div
      data-component="dossier-folder-sheet"
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
      {...rest}
    >
      {props.children}
    </div>
  )
}

export interface DossierCardProps extends ComponentProps<"div"> {
  title?: string
  badge?: string | number
  actions?: JSX.Element
}

export function DossierCard(props: DossierCardProps) {
  const [split, rest] = splitProps(props, [
    "title",
    "badge",
    "actions",
    "class",
    "classList",
    "children",
  ])

  return (
    <div
      data-component="dossier-card"
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
      {...rest}
    >
      <Show when={split.title}>
        <div data-component="dossier-card-header">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold text-text-primary tracking-tight">
              {split.title}
            </span>
            <Show when={split.badge !== undefined}>
              <span class="rounded bg-bg-elevated px-1.5 py-0.5 text-xs font-mono tabular-nums text-text-secondary border border-border-weaker-base">
                {split.badge}
              </span>
            </Show>
          </div>
          <Show when={split.actions}>
            <div class="flex items-center gap-1.5">{split.actions}</div>
          </Show>
        </div>
      </Show>
      <div class="p-4">{split.children}</div>
    </div>
  )
}
