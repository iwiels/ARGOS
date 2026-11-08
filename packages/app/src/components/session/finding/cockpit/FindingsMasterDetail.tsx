import { createMemo, createSignal, For, Show } from "solid-js"
import { FindingCompactCard } from "./FindingCompactCard"
import { FindingInspector } from "./FindingInspector"
import type { FeedbackVerdict } from "../../findings-data"
import type { CockpitFinding } from "./cockpit-types"

export function FindingsMasterDetail(props: {
  findings: CockpitFinding[]
  selectedFindingId: string | undefined
  onSelectFinding: (id: string) => void
  onStatusChange: (id: string, nextStatus: string) => void
  onFeedback?: (id: string, verdict: FeedbackVerdict) => Promise<void> | void
  feedbackPending?: boolean
  onResetFilters?: () => void
  onReverify?: (id: string) => Promise<void> | void
  reverifying?: boolean
  reverifyMessage?: string
}) {
  const [showMobileInspector, setShowMobileInspector] = createSignal(false)

  const selectedFinding = createMemo(() => {
    return props.findings.find((f) => f.id === props.selectedFindingId) || props.findings[0]
  })

  return (
    <div class="@container grid grid-cols-1 @2xl:grid-cols-12 min-h-0 flex-1 overflow-hidden h-full">
      {/* Columna izquierda: lista a 7 columnas */}
      <div class={`@2xl:col-span-7 overflow-y-auto px-4 sm:px-6 py-3 flex flex-col gap-2 min-h-0 ${showMobileInspector() ? "hidden @2xl:flex" : "flex"}`}>
        <Show
          when={props.findings.length > 0}
          fallback={
            <div class="py-16 text-center">
              <p class="text-sm text-text-tertiary">{"No hay hallazgos con los filtros actuales."}</p>
              <Show when={props.onResetFilters}>
                <button
                  type="button"
                  onClick={() => props.onResetFilters?.()}
                  class="mt-3 text-xs text-text-primary underline underline-offset-2 hover:opacity-80 transition-opacity"
                >
                  {"Restablecer filtros"}
                </button>
              </Show>
            </div>
          }
        >
          <For each={props.findings}>
            {(finding) => (
              <FindingCompactCard
                finding={finding}
                isSelected={finding.id === (selectedFinding()?.id ?? "")}
                onSelect={() => {
                  props.onSelectFinding(finding.id)
                  setShowMobileInspector(true)
                }}
                onStatusChange={(nextStatus) => props.onStatusChange(finding.id, nextStatus)}
              />
            )}
          </For>
        </Show>
      </div>

      {/* Columna derecha: Inspector pericial a 5 columnas */}
      <div class={`@2xl:col-span-5 overflow-y-auto border-t @2xl:border-t-0 @2xl:border-l border-border-weaker-base p-4 sm:p-6 bg-bg-surface/20 min-h-0 ${showMobileInspector() ? "block" : "hidden @2xl:block"}`}>
        <Show when={showMobileInspector()}>
          <div class="@2xl:hidden pb-3 border-b border-border-weaker-base mb-4">
            <button
              type="button"
              onClick={() => setShowMobileInspector(false)}
              class="inline-flex items-center gap-1.5 text-xs text-text-secondary hover:text-text-primary transition-colors"
            >
              <span>{"←"}</span>
              <span>{"Volver a la lista de hallazgos"}</span>
            </button>
          </div>
        </Show>
        <FindingInspector
          finding={selectedFinding()}
          onStatusChange={(nextStatus) => {
            const current = selectedFinding()
            if (current) props.onStatusChange(current.id, nextStatus)
          }}
          onReverify={() => {
            const current = selectedFinding()
            if (current) void props.onReverify?.(current.id)
          }}
          onFeedback={(verdict) => {
            const current = selectedFinding()
            if (current) void props.onFeedback?.(current.id, verdict)
          }}
          feedbackPending={props.feedbackPending}
          reverifying={props.reverifying}
          reverifyMessage={props.reverifyMessage}
        />
      </div>
    </div>
  )
}
