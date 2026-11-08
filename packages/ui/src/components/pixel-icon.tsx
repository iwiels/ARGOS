import { type ComponentProps, splitProps } from "solid-js"
import { PIXEL_ICONS } from "./pixel-icons.data"

export type PixelIconName = keyof typeof PIXEL_ICONS | string

export interface PixelIconProps extends ComponentProps<"svg"> {
  name: PixelIconName
  size?: number | "small" | "normal" | "large"
}

const SIZE_MAP = {
  small: 16,
  normal: 20,
  large: 24,
}

export function PixelIcon(props: PixelIconProps) {
  const [split, rest] = splitProps(props, ["name", "size", "class", "classList", "style"])

  const computedSize = () => {
    if (typeof split.size === "number") return split.size
    if (split.size && split.size in SIZE_MAP) return SIZE_MAP[split.size as keyof typeof SIZE_MAP]
    return 16
  }

  const pathData = () => PIXEL_ICONS[split.name] ?? ""

  return (
    <svg
      viewBox="0 0 32 32"
      width={computedSize()}
      height={computedSize()}
      fill="currentColor"
      aria-hidden="true"
      data-component="pixel-icon"
      data-icon={split.name}
      style={{
        ...(typeof split.style === "object" ? split.style : {}),
        "shape-rendering": "crispEdges",
      }}
      classList={{
        "shrink-0 inline-block align-middle": true,
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
      {...rest}
    >
      <path d={pathData()} fill="currentColor" />
    </svg>
  )
}
