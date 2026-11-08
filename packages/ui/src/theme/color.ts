import type { HexColor } from "./types"

export function withAlpha(color: HexColor, alpha: number): string {
  const h = color.replace("#", "")
  const full =
    h.length === 3 || h.length === 4
      ? h
          .split("")
          .map((c) => c + c)
          .join("")
      : h
  const rgb = full.length === 8 ? full.slice(0, 6) : full

  const num = parseInt(rgb, 16)
  const r = ((num >> 16) & 255) / 255
  const g = ((num >> 8) & 255) / 255
  const b = (num & 255) / 255
  return `rgba(${Math.round(r * 255)}, ${Math.round(g * 255)}, ${Math.round(b * 255)}, ${alpha})`
}
