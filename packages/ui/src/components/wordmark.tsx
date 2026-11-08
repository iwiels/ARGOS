import { type ComponentProps } from "solid-js"

export function Wordmark(props: Pick<ComponentProps<"svg">, "class">) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 360.002 129.001"
      fill="none"
      preserveAspectRatio="xMidYMid meet"
      classList={{ [props.class ?? ""]: !!props.class }}
    >
      <text
        x="180"
        y="98"
        text-anchor="middle"
        font-family="Inter, system-ui, -apple-system, sans-serif"
        font-size="104"
        font-weight="800"
        letter-spacing="-4"
        fill="currentColor"
      >
        Argos
      </text>
    </svg>
  )
}
