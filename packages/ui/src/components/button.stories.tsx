import { Button } from "./button"

const docs = `### Overview
Button v2 with three visual variants and two sizes.

### API
- \`variant\`: "neutral" | "contrast" | "ghost" | "ghost-muted".
- \`size\`: "normal" | "large".
- \`icon\`: Optional icon name.
- Inherits Kobalte Button props and native button attributes.

### States
- default, hover, pressed, focus, disabled.
- State selectors are available via pseudo-classes and \`[data-state]\`.
`

export default {
  title: "UI V2/Button",
  id: "components-button-v2",
  component: Button,
  tags: ["autodocs"],
  parameters: {
    frameHeight: "240px",
    frameBackground: "#fff",
    docs: {
      description: {
        component: docs,
      },
    },
  },
  args: {
    children: "Button",
    variant: "neutral",
    size: "normal",
  },
  argTypes: {
    icon: {
      control: "text",
    },
    variant: {
      control: "select",
      options: ["neutral", "contrast", "ghost", "ghost-muted"],
    },
    size: {
      control: "select",
      options: ["normal", "large"],
    },
  },
}

export const Playground = {}

export const Variants = {
  render: () => (
    <div
      style={{
        display: "flex",
        gap: "12px",
        "align-items": "center",
        "flex-wrap": "wrap",
      }}
    >
      <Button variant="neutral">Neutral</Button>
      <Button variant="contrast">Contrast</Button>
      <Button variant="ghost">Ghost</Button>
      <Button variant="ghost-muted" icon="edit">
        Ghost muted
      </Button>
    </div>
  ),
}

export const Sizes = {
  render: () => (
    <div
      style={{
        display: "flex",
        gap: "12px",
        "align-items": "center",
        "flex-wrap": "wrap",
      }}
    >
      <Button size="small" variant="neutral">
        Small
      </Button>
      <Button size="normal" variant="neutral">
        Normal
      </Button>
      <Button size="large" variant="neutral">
        Large
      </Button>
    </div>
  ),
}

export const Icon = {
  render: () => (
    <div
      style={{
        display: "flex",
        gap: "12px",
        "align-items": "center",
        "flex-wrap": "wrap",
      }}
    >
      <Button variant="neutral" size="normal" icon="plus">
        Normal
      </Button>
      <Button variant="contrast" size="large" icon="plus">
        Large
      </Button>
    </div>
  ),
}

export const AllStates = {
  render: () => {
    const variants = ["neutral", "contrast", "ghost", "ghost-muted"] as const
    const states = ["default", "hover", "pressed", "focus", "disabled"] as const
    const toTitleCase = (value: string) => value.charAt(0).toUpperCase() + value.slice(1)
    return (
      <div style={{ display: "grid", gap: "12px" }}>
        {variants.map((variant) => (
          <div style={{ display: "grid", gap: "8px" }}>
            <div
              style={{
                "font-size": "12px",
                color: "var(--text-weak)",
                "text-transform": "capitalize",
              }}
            >
              {variant}
            </div>
            <div style={{ display: "flex", gap: "8px", "flex-wrap": "wrap" }}>
              {states.map((state) => (
                <Button
                  variant={variant}
                  data-state={state === "default" ? undefined : state}
                  disabled={state === "disabled"}
                >
                  {toTitleCase(state)}
                </Button>
              ))}
            </div>
          </div>
        ))}
      </div>
    )
  },
}

