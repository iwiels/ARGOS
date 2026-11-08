// @ts-nocheck
import { Callout, CalloutActions, CalloutDescription, CalloutTitle } from "./card"
import { Button } from "./button"

const docs = `### Overview
Callout, not a box: transparent surface with a 2px lateral accent line.
For bordered container boxes use \`SurfaceCard\`.

Pair with \`Button\` or \`Tag\` for quick actions.

### API
- Optional: \`variant\` (normal, error, warning, success, info).
- Accepts standard div props.

### Variants and states
- Semantic variants for status-driven messaging.

### Behavior
- Pure presentational container.

### Accessibility
- Provide headings or aria labels when used in isolation.

### Theming/tokens
- Uses \`data-component="callout"\` with variant data attributes.

`

export default {
  title: "UI/Callout",
  id: "components-callout",
  component: Callout,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: docs,
      },
    },
  },
  args: {
    variant: "normal",
  },
  argTypes: {
    variant: {
      control: "select",
      options: ["normal", "error", "warning", "success", "info"],
    },
  },
  render: (props: { variant?: "normal" | "error" | "warning" | "success" | "info" }) => {
    return (
      <Callout variant={props.variant}>
        <CalloutTitle variant={props.variant}>Callout title</CalloutTitle>
        <CalloutDescription>Small supporting text.</CalloutDescription>
        <CalloutActions>
          <Button size="small" variant="neutral">
            Action
          </Button>
        </CalloutActions>
      </Callout>
    )
  },
}

export const Normal = {}

export const Error = {
  args: {
    
  },
}

export const Warning = {
  args: {
    variant: "warning",
  },
}

export const Success = {
  args: {
    
  },
}

export const Info = {
  args: {
    variant: "info",
  },
}
