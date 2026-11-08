import { SessionV2 } from "@argos/core/session"
import { LocationServiceMap } from "@argos/core/location-layer"
import { Database } from "@argos/core/database/database"
import { EventV2 } from "@argos/core/event"
import { ProjectV2 } from "@argos/core/project"
import { SessionProjector } from "@argos/core/session/projector"
import { SessionStore } from "@argos/core/session/store"
import { PermissionSaved } from "@argos/core/permission/saved"
import { Audit } from "@argos/core/audit"
import { Layer } from "effect"
import { layer as locationLayer } from "./groups/location"
import { sessionLocationLayer } from "./middleware/session-location"
import { MessageHandler } from "./handlers/message"
import { ModelHandler } from "./handlers/model"
import { ProviderHandler } from "./handlers/provider"
import { SessionHandler } from "./handlers/session"
import { PermissionHandler } from "./handlers/permission"
import { FileSystemHandler } from "./handlers/fs"
import { CommandHandler } from "./handlers/command"
import { SkillHandler } from "./handlers/skill"
import { EventHandler } from "./handlers/event"
import { AgentHandler } from "./handlers/agent"
import { HealthHandler } from "./handlers/health"
import { QuestionHandler } from "./handlers/question"
import * as SessionExecutionLocal from "@argos/core/session/execution/local"
import { SecurityHandler } from "./handlers/security"
import { ComplianceHandler } from "./handlers/compliance"
import { Compliance } from "@argos/core/compliance"

const sessionRuntime = SessionV2.layer.pipe(
  Layer.provide(SessionProjector.defaultLayer),
  Layer.provide(SessionStore.defaultLayer),
  Layer.provide(EventV2.defaultLayer),
  Layer.provide(Database.defaultLayer),
  Layer.provide(ProjectV2.defaultLayer),
  Layer.provide(SessionExecutionLocal.defaultLayer),
  Layer.orDie,
)

export const handlers = Layer.mergeAll(
  HealthHandler,
  AgentHandler,
  SessionHandler,
  MessageHandler,
  ModelHandler,
  ProviderHandler,
  PermissionHandler,
  FileSystemHandler,
  CommandHandler,
  SkillHandler,
  EventHandler,
  QuestionHandler,
  SecurityHandler,
  ComplianceHandler,
).pipe(
  Layer.provide(Audit.defaultLayer),
  Layer.provide(Compliance.defaultLayer),
  Layer.provide(sessionLocationLayer),
  Layer.provide(locationLayer),
  Layer.provide(sessionRuntime),
  Layer.provide(PermissionSaved.defaultLayer),
  Layer.provide(LocationServiceMap.layer),
)
