import type { Session } from "@argos/sdk/client"
import type { LocalProject } from "@/context/layout"

export type AuditSession = Session & {
  type?: "web" | "red" | "recon" | "full" | (string & {})
}

export type HomeSessionRecord = {
  session: AuditSession
  project: LocalProject
  projectName: string
}

export type HomeSessionGroup = {
  id: "today" | "yesterday" | "older"
  title: string
  sessions: HomeSessionRecord[]
}
