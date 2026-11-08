import type { Component, JSX } from "solid-js"
import { createMemo, splitProps } from "solid-js"
import { iconNames, type IconName } from "./provider-icons/types"

export type ProviderIconProps = JSX.SVGElementTags["svg"] & {
  id: string
}

const rawIcons = import.meta.glob("../assets/icons/provider/*.svg", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>

type IconData = {
  viewBox: string
  fill?: string
  body: string
}

const parsedIcons: Record<string, IconData> = {}

for (const [path, raw] of Object.entries(rawIcons)) {
  const id = path.split(/[/\\]/).pop()?.replace(/\.svg$/, "")
  if (!id) continue
  const viewBoxMatch = raw.match(/viewBox=["']([^"']+)["']/)
  const fillMatch = raw.match(/<svg[^>]*\sfill=["']([^"']+)["']/)
  const bodyMatch = raw.match(/<svg[^>]*>([\s\S]*?)<\/svg>/)
  parsedIcons[id] = {
    viewBox: viewBoxMatch ? viewBoxMatch[1] : "0 0 24 24",
    fill: fillMatch ? fillMatch[1] : undefined,
    body: bodyMatch ? bodyMatch[1] : raw,
  }
}

export const ProviderIcon: Component<ProviderIconProps> = (props) => {
  const [local, rest] = splitProps(props, ["id", "class", "classList"])
  const resolved = createMemo(() => (iconNames.includes(local.id as IconName) ? local.id : "synthetic"))
  const icon = createMemo(() => parsedIcons[resolved()] ?? parsedIcons["synthetic"])

  return (
    <svg
      data-component="provider-icon"
      viewBox={icon()?.viewBox ?? "0 0 24 24"}
      fill={icon()?.fill ?? "none"}
      innerHTML={icon()?.body ?? ""}
      {...rest}
      classList={{
        ...local.classList,
        [local.class ?? ""]: !!local.class,
      }}
    />
  )
}

