import { type ComponentProps, splitProps } from "solid-js"
import { Icon, type IconProps } from "./icon"

/**
 * Callout, not a box: transparent surface with no border and a 2px lateral
 * accent line (`::before`). For bordered container boxes use `SurfaceCard`.
 */
type CalloutVariant = "normal" | "error" | "warning" | "success" | "info"

export interface CalloutProps extends ComponentProps<"div"> {
  variant?: CalloutVariant
}

export interface CalloutTitleProps extends ComponentProps<"div"> {
  variant?: CalloutVariant

  /**
   * Optional title icon.
   *
   * - `undefined`: picks a default icon based on `variant` (error/warning/success/info)
   * - `false`/`null`: disables the icon
   * - `Icon` name: forces a specific icon
   */
  icon?: IconProps["name"] | false | null
}

function pick(variant: CalloutVariant) {
  if (variant === "error") return "circle-ban-sign" as const
  if (variant === "warning") return "warning" as const
  if (variant === "success") return "circle-check" as const
  if (variant === "info") return "help" as const
  return
}

function mix(style: ComponentProps<"div">["style"], value?: string) {
  if (!value) return style
  if (!style) return { "--card-accent": value }
  if (typeof style === "string") return `${style};--card-accent:${value};`
  return { ...(style as Record<string, string | number>), "--card-accent": value }
}

export function Callout(props: CalloutProps) {
  const [split, rest] = splitProps(props, ["variant", "style", "class", "classList"])
  const variant = () => split.variant ?? "normal"
  const accent = () => {
    const v = variant()
    if (v === "error") return "var(--icon-critical-base)"
    if (v === "warning") return "var(--icon-warning-active)"
    if (v === "success") return "var(--icon-success-active)"
    if (v === "info") return "var(--icon-info-active)"
    return
  }
  return (
    <div
      {...rest}
      data-component="callout"
      data-variant={variant()}
      style={mix(split.style, accent())}
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
    >
      {props.children}
    </div>
  )
}

export function CalloutTitle(props: CalloutTitleProps) {
  const [split, rest] = splitProps(props, ["variant", "icon", "class", "classList", "children"])
  const show = () => split.icon !== false && split.icon !== null
  const name = () => {
    if (split.icon === false || split.icon === null) return
    if (typeof split.icon === "string") return split.icon
    return pick(split.variant ?? "normal")
  }
  const placeholder = () => !name()
  return (
    <div
      {...rest}
      data-slot="callout-title"
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
    >
      {show() ? (
        <span data-slot="callout-title-icon" data-placeholder={placeholder() || undefined}>
          <Icon name={name() ?? "dash"} size="small" />
        </span>
      ) : null}
      {split.children}
    </div>
  )
}

export function CalloutDescription(props: ComponentProps<"div">) {
  const [split, rest] = splitProps(props, ["class", "classList", "children"])
  return (
    <div
      {...rest}
      data-slot="callout-description"
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
    >
      {split.children}
    </div>
  )
}

export function CalloutActions(props: ComponentProps<"div">) {
  const [split, rest] = splitProps(props, ["class", "classList", "children"])
  return (
    <div
      {...rest}
      data-slot="callout-actions"
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
    >
      {split.children}
    </div>
  )
}

/** @deprecated Use `Callout` instead (same callout pattern, honest name). */
export const Card = Callout
/** @deprecated Use `CalloutTitle` instead. */
export const CardTitle = CalloutTitle
/** @deprecated Use `CalloutDescription` instead. */
export const CardDescription = CalloutDescription
/** @deprecated Use `CalloutActions` instead. */
export const CardActions = CalloutActions
/** @deprecated Use `CalloutProps` instead. */
export type CardProps = CalloutProps
/** @deprecated Use `CalloutTitleProps` instead. */
export type CardTitleProps = CalloutTitleProps
