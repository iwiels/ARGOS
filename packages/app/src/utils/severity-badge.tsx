import type { JSX } from "solid-js"
import type { Severity } from "@/components/session/findings-data"
import { SEV_BADGE } from "./severity"

/**
 * Tono de severidad centralizado (tokens `--severity-*` vía `SEV_BADGE`).
 * Punto único para el color de severidad en pills/badges de app.
 */
export function severityBadgeTone(severity: Severity): string {
  return SEV_BADGE[severity]
}

const NEUTRAL_TONE = "border-border-weaker-base bg-bg-surface text-text-secondary"

/**
 * `SeverityBadge` único sobre tokens `--severity-*` (02-components.md §7#14).
 *
 * Span por defecto; con `as="button"` renderiza el toggle con semántica de
 * acción (las pills-toggle de severidad no tienen variante equivalente en
 * `<Button>`: doble tono severidad/neutro + contador + `rounded-full`).
 * Con `muted` el toggle inactivo usa el tono neutro en vez del de severidad.
 */
export function SeverityBadge(props: {
  severity: Severity
  class?: string
  children?: JSX.Element
  as?: "span" | "button"
  pressed?: boolean
  muted?: boolean
  onClick?: (event: MouseEvent) => void
}) {
  const tone = () => (props.muted ? NEUTRAL_TONE : severityBadgeTone(props.severity))
  const cls = () => `inline-flex items-center border ${tone()}${props.class ? ` ${props.class}` : ""}`
  return props.as === "button" ? (
    <button type="button" class={cls()} aria-pressed={props.pressed} onClick={props.onClick}>
      {props.children}
    </button>
  ) : (
    <span class={cls()}>{props.children}</span>
  )
}
