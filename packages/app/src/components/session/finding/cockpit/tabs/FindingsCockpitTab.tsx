import { AttckFilterBar } from "../AttckFilterBar"
import { FindingsMasterDetail } from "../FindingsMasterDetail"
import type { FeedbackVerdict } from "../../../findings-data"
import type { CockpitFinding } from "../cockpit-types"

export function FindingsCockpitTab(props: {
  findings: CockpitFinding[]
  selectedFindingId: string | undefined
  onSelectFinding: (id: string) => void
  onStatusChange: (id: string, nextStatus: string) => void
  onFeedback?: (id: string, verdict: FeedbackVerdict) => Promise<void> | void
  feedbackPending?: boolean
  techniques: { id: string; name: string }[]
  activeTechnique: string | null
  onSelectTechnique: (id: string) => void
  search: string
  onSearchChange: (query: string) => void
  onResetFilters?: () => void
  onReverify?: (id: string) => Promise<void> | void
  reverifying?: boolean
  reverifyMessage?: string
}) {
  return (
    <section class="flex-1 flex flex-col min-h-0 overflow-hidden h-full">
      <AttckFilterBar
        techniques={props.techniques}
        activeTechnique={props.activeTechnique}
        onSelectTechnique={props.onSelectTechnique}
        search={props.search}
        onSearchChange={props.onSearchChange}
      />
      <FindingsMasterDetail
        findings={props.findings}
        selectedFindingId={props.selectedFindingId}
        onSelectFinding={props.onSelectFinding}
        onStatusChange={props.onStatusChange}
        onFeedback={props.onFeedback}
        feedbackPending={props.feedbackPending}
        onResetFilters={props.onResetFilters}
        onReverify={props.onReverify}
        reverifying={props.reverifying}
        reverifyMessage={props.reverifyMessage}
      />
    </section>
  )
}
