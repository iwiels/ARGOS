import type { JSX } from "solid-js"

export function ArgosIcon(props: {
  size?: number | string
  class?: string
  colorMode?: "brand" | "monochrome"
}): JSX.Element {
  const size = () => typeof props.size === "number" ? `${props.size}px` : props.size ?? "24px"
  const accent = () => props.colorMode === "monochrome" ? "currentColor" : "#34D399"
  return (
    <svg data-component="argos-icon" viewBox="0 0 256 256" fill="none" xmlns="http://www.w3.org/2000/svg" width={props.size ?? 24} height={props.size ?? 24} style={{ width: size(), height: size() }} class={props.class} aria-hidden="true">
      <path d="M128 16 224 58V136L204 180 128 240 52 180 32 136V58Z" fill={accent()} />
      <path d="M128 33 208 68V132L191 168 128 220 65 168 48 132V68Z" fill="#101C27" />
      <path d="M60 124C80 100 104 88 128 88S176 100 196 124C176 148 152 160 128 160S80 148 60 124Z" fill={accent()} />
      <circle cx="128" cy="124" r="22" fill="#101C27" />
      <circle cx="128" cy="124" r="6" fill={props.colorMode === "monochrome" ? "currentColor" : "#F0FDFA"} />
    </svg>
  )
}
