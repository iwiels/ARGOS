// @ts-nocheck
import { Badge } from "./badge"

const docs = `### Overview
Unstyled inline wrapper (no CSS of its own).

For the styled metadata/status chip use \`Tag\` from \`./tag\`
(the single \`data-component="tag"\` primitive).

### API
- Accepts standard span props.

### Accessibility
- Ensure text conveys meaning; avoid color-only distinction.

### Theming/tokens
- Uses \`data-component="badge"\` (unstyled by design).

`

export default {
  title: "UI V2/Badge",
  id: "components-badge-v2",
  component: Badge,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: docs,
      },
    },
  },
  args: {
    children: "Label",
  },
}

export const Basic = {}
