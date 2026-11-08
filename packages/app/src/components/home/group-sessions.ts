import { DateTime } from "luxon"
import type { HomeSessionRecord, HomeSessionGroup } from "./types"

export function groupSessions(
  records: HomeSessionRecord[],
  t: (key: string, params?: Record<string, string | number | boolean>) => string,
): HomeSessionGroup[] {
  const now = DateTime.local()
  const yesterday = now.minus({ days: 1 })
  const todaySessions = records.filter((record) =>
    DateTime.fromMillis(record.session.time.updated ?? record.session.time.created).hasSame(now, "day"),
  )
  const yesterdaySessions = records.filter((record) =>
    DateTime.fromMillis(record.session.time.updated ?? record.session.time.created).hasSame(yesterday, "day"),
  )
  const olderSessions = records.filter((record) => {
    const time = DateTime.fromMillis(record.session.time.updated ?? record.session.time.created)
    return !time.hasSame(now, "day") && !time.hasSame(yesterday, "day")
  })
  const olderTitle =
    todaySessions.length === 0 && yesterdaySessions.length === 0
      ? t("sidebar.project.recentSessions")
      : t("home.sessions.group.older")

  return [
    { id: "today" as const, title: t("home.sessions.group.today"), sessions: todaySessions },
    { id: "yesterday" as const, title: t("home.sessions.group.yesterday"), sessions: yesterdaySessions },
    { id: "older" as const, title: olderTitle, sessions: olderSessions },
  ].filter((group) => group.sessions.length > 0)
}


