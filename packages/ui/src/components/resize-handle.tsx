import { splitProps, type JSX } from "solid-js"

export interface ResizeHandleLabels {
  resize?: string
  pixels?: string
}

export interface ResizeHandleProps extends Omit<JSX.HTMLAttributes<HTMLDivElement>, "onResize"> {
  direction: "horizontal" | "vertical"
  edge?: "start" | "end"
  size: number
  min: number
  max: number
  onResize: (size: number) => void
  onCollapse?: () => void
  collapseThreshold?: number
  labels?: ResizeHandleLabels
}

const DEFAULT_LABELS: Required<ResizeHandleLabels> = { resize: "Redimensionar panel", pixels: "píxeles" }

export function ResizeHandle(props: ResizeHandleProps) {
  const [local, rest] = splitProps(props, [
    "direction",
    "edge",
    "size",
    "min",
    "max",
    "onResize",
    "onCollapse",
    "collapseThreshold",
    "labels",
    "aria-label",
    "aria-valuetext",
    "class",
    "classList",
  ])

  const labels = () => ({ ...DEFAULT_LABELS, ...local.labels })

  const clamp = (value: number) => Math.min(local.max, Math.max(local.min, value))

  const handleMouseDown = (e: MouseEvent) => {
    e.preventDefault()
    const edge = local.edge ?? (local.direction === "vertical" ? "start" : "end")
    const start = local.direction === "horizontal" ? e.clientX : e.clientY
    const startSize = local.size
    let current = startSize

    document.body.style.userSelect = "none"
    document.body.style.overflow = "hidden"

    const onMouseMove = (moveEvent: MouseEvent) => {
      const pos = local.direction === "horizontal" ? moveEvent.clientX : moveEvent.clientY
      const delta =
        local.direction === "vertical"
          ? edge === "end"
            ? pos - start
            : start - pos
          : edge === "start"
            ? start - pos
            : pos - start
      current = startSize + delta
      local.onResize(clamp(current))
    }

    const onMouseUp = () => {
      document.body.style.userSelect = ""
      document.body.style.overflow = ""
      document.removeEventListener("mousemove", onMouseMove)
      document.removeEventListener("mouseup", onMouseUp)

      const threshold = local.collapseThreshold ?? 0
      if (local.onCollapse && threshold > 0 && current < threshold) {
        local.onCollapse()
      }
    }

    document.addEventListener("mousemove", onMouseMove)
    document.addEventListener("mouseup", onMouseUp)
  }

  const handleKeyDown = (e: KeyboardEvent) => {
    const step = local.direction === "horizontal" ? 20 : 10
    const isRtl = local.direction === "horizontal" && document.dir === "rtl"
    let next = local.size

    if (e.key === "ArrowLeft") next += isRtl ? step : -step
    else if (e.key === "ArrowRight") next += isRtl ? -step : step
    else if (e.key === "ArrowUp") next += local.direction === "vertical" ? -step : 0
    else if (e.key === "ArrowDown") next += local.direction === "vertical" ? step : 0
    else if (e.key === "Home") next = local.min
    else if (e.key === "End") next = local.max
    else return

    e.preventDefault()
    local.onResize(clamp(next))
  }

  return (
    <div
      {...rest}
      role="separator"
      tabindex={0}
      aria-label={local["aria-label"] ?? labels().resize}
      aria-valuenow={local.size}
      aria-valuetext={local["aria-valuetext"] ?? `${Math.round(local.size)} ${labels().pixels}`}
      aria-valuemin={local.min}
      aria-valuemax={local.max}
      aria-orientation={local.direction}
      data-component="resize-handle"
      data-direction={local.direction}
      data-edge={local.edge ?? (local.direction === "vertical" ? "start" : "end")}
      classList={{
        ...local.classList,
        [local.class ?? ""]: !!local.class,
      }}
      onMouseDown={handleMouseDown}
      onKeyDown={handleKeyDown}
    />
  )
}
