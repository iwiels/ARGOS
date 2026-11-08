import { FetchHttpClient } from "effect/unstable/http"
import { Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { FSUtil } from "@argos/core/fs-util"
import { Auth } from "../../src/auth"
import { Workspace } from "../../src/control-plane/workspace"
import { RuntimeFlags } from "../../src/effect/runtime-flags"
import { InstanceBootstrap } from "../../src/project/bootstrap"
import { InstanceStore } from "../../src/project/instance-store"
import { Project } from "../../src/project/project"
import { Vcs } from "../../src/project/vcs"
import { Session } from "../../src/session/session"
import { SessionPrompt } from "../../src/session/prompt"
import { EventBridge } from "../../src/event-bridge"

export const workspaceLayerWithRuntimeFlags = (overrides: Partial<RuntimeFlags.Info>) =>
  Workspace.layer.pipe(
    Layer.provide(Auth.defaultLayer),
    Layer.provide(Session.defaultLayer),
    Layer.provide(SessionPrompt.defaultLayer),
    Layer.provide(Project.defaultLayer),
    Layer.provide(Vcs.defaultLayer),
    Layer.provide(Database.defaultLayer),
    Layer.provide(EventBridge.defaultLayer),
    Layer.provide(FetchHttpClient.layer),
    Layer.provide(FSUtil.defaultLayer),
    Layer.provide(RuntimeFlags.layer(overrides)),
    Layer.provide(InstanceStore.defaultLayer),
    Layer.provide(InstanceBootstrap.defaultLayer),
  )
