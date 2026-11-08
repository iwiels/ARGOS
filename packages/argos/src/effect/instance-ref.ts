import { Context } from "effect"
import type { InstanceContext } from "@/project/instance-context"
import type { WorkspaceV2 } from "@argos/core/workspace"

export const InstanceRef = Context.Reference<InstanceContext | undefined>("~argos/InstanceRef", {
  defaultValue: () => undefined,
})

export const WorkspaceRef = Context.Reference<WorkspaceV2.ID | undefined>("~argos/WorkspaceRef", {
  defaultValue: () => undefined,
})
