import type { VirtualizerHandle } from "virtua/solid"
import type { Part as PartType } from "@argos/sdk/client"
import { shouldMarkBoundaryGesture } from "./message-gesture"
import { TimelineRow } from "./message-timeline.data"

/**
 * Timeline virtualizer measurement cache (LRU by session id) + scroll/
 * gesture boundary helpers. Extracted from message-timeline.tsx (C1 split).
 *
 * Note: kept out of message-timeline-helpers.ts on purpose — helpers has a
 * bun-run test file and must not transitively import Vite-only modules
 * (import.meta.glob) via the data/ui chain.
 */

export const timelineCacheLimit = 16
export const timelineFallbackItemSize = 60

const timelineCache = new Map<string, { keys: readonly string[]; cache: VirtualizerHandle["cache"] }>()

export function sameKeys(a: readonly string[] | undefined, b: readonly string[] | undefined) {
  if (a === b) return true
  if (!a || !b) return false
  if (a.length !== b.length) return false
  return a.every((key, index) => key === b[index])
}

export function readTimelineCache(id: string, keys: readonly string[]) {
  const entry = timelineCache.get(id)
  if (!entry) return
  if (sameKeys(entry.keys, keys)) return entry.cache
  timelineCache.delete(id)
}

export function writeTimelineCache(id: string, keys: readonly string[], handle: VirtualizerHandle | undefined) {
  if (!handle || keys.length === 0) return
  timelineCache.delete(id)
  timelineCache.set(id, { keys: keys.slice(), cache: handle.cache })
  while (timelineCache.size > timelineCacheLimit) timelineCache.delete(timelineCache.keys().next().value!)
}

export function reuseTimelineRows(previous: TimelineRow.TimelineRow[] | undefined, rows: TimelineRow.TimelineRow[]) {
  if (!previous?.length) return rows
  const byKey = new Map(previous.map((row) => [TimelineRow.key(row), row] as const))
  return rows.map((row) => {
    const existing = byKey.get(TimelineRow.key(row))
    if (!existing) return row
    return TimelineRow.equals(existing, row) ? existing : row
  })
}

export const taskDescription = (part: PartType, sessionID: string) => {
  if (part.type !== "tool" || part.tool !== "task") return
  const metadata = "metadata" in part.state ? part.state.metadata : undefined
  if (metadata?.sessionId !== sessionID) return
  const value = part.state.input?.description
  if (typeof value === "string" && value) return value
}

export const pace = (width: number) => Math.round(Math.max(1200, Math.min(3200, (Math.max(width, 360) * 2000) / 900)))

export const boundaryTarget = (root: HTMLElement, target: EventTarget | null) => {
  const current = target instanceof Element ? target : undefined
  const nested = current?.closest("[data-scrollable]")
  if (!nested || nested === root) return root
  if (!(nested instanceof HTMLElement)) return root
  return nested
}

export const markBoundaryGesture = (input: {
  root: HTMLDivElement
  target: EventTarget | null
  delta: number
  onMarkScrollGesture: (target?: EventTarget | null) => void
}) => {
  const target = boundaryTarget(input.root, input.target)
  if (target === input.root) {
    input.onMarkScrollGesture(input.root)
    return
  }
  if (
    shouldMarkBoundaryGesture({
      delta: input.delta,
      scrollTop: target.scrollTop,
      scrollHeight: target.scrollHeight,
      clientHeight: target.clientHeight,
    })
  ) {
    input.onMarkScrollGesture(input.root)
  }
}
