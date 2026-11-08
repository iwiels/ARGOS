import { bindFindingsToSession, mergeFindings, type Finding } from "../components/session/findings-data"

export function selectSessionFindings(
  sessionID: string,
  persisted: Finding[],
  live: Finding[],
  persistedOnly = false,
): Finding[] {
  const saved = bindFindingsToSession(
    persisted.filter((finding) => finding.source !== "tool" && (!finding.session || finding.session === sessionID)),
    sessionID,
  )
  if (persistedOnly) return saved
  return mergeFindings(saved, bindFindingsToSession(live, sessionID))
}
