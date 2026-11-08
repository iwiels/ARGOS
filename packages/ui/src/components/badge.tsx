import { type ComponentProps, splitProps } from "solid-js"

export interface BadgeProps extends ComponentProps<"span"> {}

/**
 * Unstyled inline wrapper. For the styled metadata/status chip use `Tag`
 * from `./tag` (the single `data-component="tag"` primitive).
 */
export function Badge(props: BadgeProps) {
  const [split, rest] = splitProps(props, ["class", "classList", "children"])
  return (
    <span
      {...rest}
      data-component="badge"
      classList={{
        ...split.classList,
        [split.class ?? ""]: !!split.class,
      }}
    >
      {split.children}
    </span>
  )
}

