import { SessionAuditProfile } from "@argos/core/session/audit-profile"
import { SessionCoverage } from "@argos/core/session/coverage"

const profiles: Record<SessionAuditProfile.ID, ReadonlyArray<SessionCoverage.Requirement>> = {
  web: [
    { surface: "web", role: "anonymous", testKey: "web.scan", runtimeTool: "web.scan" },
    { surface: "web", role: "anonymous", testKey: "web.waf", runtimeTool: "web.waf" },
    { surface: "web", role: "anonymous", testKey: "web.csrf", runtimeTool: "web.csrf" },
    { surface: "web", role: "anonymous", testKey: "web.graphql", runtimeTool: "web.graphql" },
    { surface: "web", role: "anonymous", testKey: "web.jwt", runtimeTool: "web.jwt" },
    { surface: "web", role: "anonymous", testKey: "web.oauth", runtimeTool: "web.oauth" },
    { surface: "web", role: "anonymous", testKey: "web.prompt_injection", runtimeTool: "web.prompt_injection" },
    { surface: "web", role: "anonymous", testKey: "web.ssti", runtimeTool: "web.ssti" },
  ],
}

export const requirements = (profile: SessionAuditProfile.ID) => profiles[profile].map((item) => ({ ...item }))
