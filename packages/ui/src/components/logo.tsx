import { type ComponentProps } from "solid-js"
import { Wordmark } from "./wordmark"
import { ArgosIcon } from "./argos-logo"

export { ArgosIcon }

export const Mark = (props: { class?: string; size?: number | string; colorMode?: "brand" | "monochrome" }) => {
  return <ArgosIcon class={props.class} size={props.size ?? 24} colorMode={props.colorMode} />
}

export const Splash = (props: Pick<ComponentProps<"svg">, "ref" | "class"> & { size?: number | string }) => {
  return <ArgosIcon class={props.class} size={props.size ?? 96} />
}

export const Logo = (props: { class?: string }) => {
  return <Wordmark class={props.class} />
}
