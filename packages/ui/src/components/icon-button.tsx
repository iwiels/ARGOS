import { Button as Kobalte } from "@kobalte/core/button"
import { type ComponentProps, splitProps } from "solid-js"
import { JSX } from "solid-js"
import { Icon } from "./icon"
import "./icon-button.css"

export interface IconButtonProps
  extends ComponentProps<typeof Kobalte>,
    Pick<ComponentProps<"button">, "class" | "classList"> {
  icon?: JSX.Element | string
  iconSize?: "small" | "normal" | "large"
  size?: "small" | "normal" | "large"
  variant?: "neutral" | "contrast" | "contrast-elevated" | "ghost" | "ghost-muted"
  state?: "rest" | "hover" | "pressed"
}

export function IconButton(props: ComponentProps<"button"> & IconButtonProps) {
  const [split, rest] = splitProps(props, ["variant", "size", "iconSize", "icon", "class", "classList", "state"])
  return (
    <Kobalte
      {...rest}
      data-component="icon-button"
      data-size={split.size || "normal"}
      data-variant={split.variant || "neutral"}
      data-state={split.state}
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
    >
      {typeof split.icon === "string" ? (
        <Icon name={split.icon} size={split.iconSize ?? (split.size === "large" ? "normal" : "small")} />
      ) : (
        split.icon
      )}
    </Kobalte>
  )
}

