/**
 * topology-panel.tsx
 *
 * Panel de topología de red para el panel lateral de sesión (session-side-panel).
 * Extrae las tool parts de la sesión actual y renderiza el TopologyCanvas.
 */

import { createMemo, Show } from "solid-js"
import { Icon } from "@argos/ui/icon"
import { TopologyCanvas } from "./topology-canvas"
import {
  selectTopologySnapshot,
  extractLanPartsFromMessages,
  DEFAULT_RISKY_PORTS,
} from "./topology-data"
import type { Finding } from "./findings-data"
import { useSync } from "@/context/sync"
import { useLanguage } from "@/context/language"
import { collectSessionFamilyIds } from "@/pages/layout/helpers"

interface TopologyPanelProps {
  sessionId: string
  findings?: Finding[]
  onClose?: () => void
}

export function TopologyPanel(props: TopologyPanelProps) {
  const sync = useSync()
  const language = useLanguage()

  const snapshot = createMemo(() => {
    const familyIds = collectSessionFamilyIds(sync.data.session, props.sessionId)
    const messages: { id: string }[] = []
    for (const sid of familyIds) {
      messages.push(...(sync.data.message[sid] ?? []))
    }
    const parts = extractLanPartsFromMessages(messages, sync.data.part as Record<string, unknown[] | undefined>)
    return selectTopologySnapshot(parts)
  })

  return (
    <div class="flex flex-col h-full overflow-hidden relative">
      <Show
        when={snapshot() && (snapshot()!.devices.length > 0 || snapshot()!.gateway)}
        fallback={
          <div class="flex flex-1 flex-col items-center justify-center gap-3 p-6 text-center">
            <Icon name="server" class="text-text-tertiary size-8 opacity-40" />
            <div class="text-xs font-mono text-text-secondary">{language.t("topology.panel.empty.title")}</div>
            <div class="text-xs text-text-tertiary max-w-70">
              {language.t("topology.panel.empty.hintPrefix")}{" "}
              <span class="font-mono text-text-primary">/auditoria-red</span>{" "}
              {language.t("topology.panel.empty.hintSuffix")}
            </div>
          </div>
        }
      >
        <div class="flex-1 relative">
          <TopologyCanvas
            devices={snapshot()!.devices}
            gateway={snapshot()!.gateway}
            riskyPorts={DEFAULT_RISKY_PORTS}
          />
        </div>
      </Show>
    </div>
  )
}

