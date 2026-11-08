import { For, Match, Show, Switch, createEffect, createMemo, createResource, onCleanup, type JSX } from "solid-js"
import { createStore } from "solid-js/store"
import { createMediaQuery } from "@solid-primitives/media"
import { Tabs } from "@argos/ui/tabs"
import { Icon } from "@argos/ui/icon"
import { ResizeHandle } from "@argos/ui/resize-handle"
import { ThinkingOrb } from "@argos/ui/thinking-orb"
import { DragDropProvider, DragDropSensors, DragOverlay, SortableProvider, closestCenter } from "@thisbeyond/solid-dnd"
import type { DragEvent } from "@thisbeyond/solid-dnd"
import type { SnapshotFileDiff, VcsFileDiff } from "@argos/sdk/client"
import { ConstrainDragYAxis, getDraggableId } from "@/utils/solid-dnd"

import FileTree from "@/components/file-tree"
import { SessionContextTab, SortableTab, FileVisual } from "@/components/session"
import { FindingsTable } from "@/components/session/findings-view"
import { FindingImportPanel } from "@/components/session/finding-import-panel"
import { extractFindings, extractWebSurface, normalizeToolParts, severityCounts, SEVERITY_LABELS } from "@/components/session/findings-data"
import { TopologyPanel } from "@/components/session/topology-panel"
import { TrafficPanel } from "@/components/session/traffic-panel"
import { extractLanPartsFromMessages, hasTopologyData, topologyPartsFromFindings } from "@/components/session/topology-data"
import { useFile, type SelectedLineRange } from "@/context/file"
import { useLanguage } from "@/context/language"
import { useLayout } from "@/context/layout"
import { usePlatform } from "@/context/platform"
import { useSettings } from "@/context/settings"
import { useSync } from "@/context/sync"
import { useSDK } from "@/context/sdk"
import { createFileTabListSync } from "@/pages/session/file-tab-scroll"
import { FileTabContent } from "@/pages/session/file-tabs"
import { createOpenSessionFileTab, createSessionTabs, getTabReorderIndex, type Sizing } from "@/pages/session/helpers"
import { collectSessionFamilyIds } from "@/pages/layout/helpers"
import { setSessionHandoff } from "@/pages/session/handoff"
import { useSessionLayout } from "@/pages/session/session-layout"
import { loadSessionFindings } from "@/components/session/security-findings-api"
import { selectSessionFindings } from "@/hooks/audit-findings-selection"
import { buildReverifyPrompt } from "@/components/session/finding-reverify"
import { ComplianceCockpitTab } from "@/components/session/finding/cockpit/tabs/ComplianceCockpitTab"
import { ExecutiveReportCockpitTab } from "@/components/session/finding/cockpit/tabs/ExecutiveReportCockpitTab"
import { mapToCockpitFinding } from "@/components/session/finding/cockpit/cockpit-data"
import type { CockpitFinding } from "@/components/session/finding/cockpit/cockpit-types"
import { targetDirFromParams } from "@/utils/target-dir"
import type { Finding } from "@/components/session/findings-data"
import { sendFollowupDraft } from "@/components/prompt-input/submit"
import { useLocal } from "@/context/local"
import { useServerSync } from "@/context/server-sync"
import { showToast } from "@/utils/toast"

type RenderDiff = (SnapshotFileDiff & { file: string }) | VcsFileDiff

function renderDiff(value: SnapshotFileDiff | VcsFileDiff): value is RenderDiff {
  return typeof value.file === "string"
}



export function SessionSidePanel(props: {
  canReview: () => boolean
  diffs: () => (SnapshotFileDiff | VcsFileDiff)[]
  diffsReady: () => boolean
  empty: () => string
  hasReview: () => boolean
  reviewCount: () => number
  reviewPanel: () => JSX.Element
  activeDiff?: string
  focusReviewDiff: (path: string) => void
  compact: () => boolean
  reviewSnap: boolean
  size: Sizing
}) {
  const layout = useLayout()
  const platform = usePlatform()
  const settings = useSettings()
  const sync = useSync()
  const serverSync = useServerSync()
  const sdk = useSDK()
  const local = useLocal()
  const file = useFile()
  const language = useLanguage()
  const { sessionKey, tabs, view, params } = useSessionLayout()

  const isDesktopQuery = createMediaQuery("(min-width: 600px)")
  const isDesktop = createMemo(() => platform.platform === "desktop" || isDesktopQuery())
  const desktopV2 = () => platform.platform === "desktop"
  const shown = createMemo(() => (desktopV2() ? settings.general.showFileTree() : true))

  const familyIds = createMemo(() => {
    const id = params.id
    if (!id) return []
    return collectSessionFamilyIds(sync.data.session, id)
  })

  const [apiFindings, { refetch: refetchFindings }] = createResource(
    () => params.id,
    async (sessionID) => {
      if (!sessionID) return undefined
      return await loadSessionFindings((...args) => sdk.request(...args), sessionID).catch(() => undefined)
    },
  )

  /**
   * El agente persiste su veredicto con la tool `finding_status` durante su
   * turno, así que el panel se entera recién cuando la sesión vuelve a idle.
   * Refrescar en esa transición evita tener que pollear la BD.
   */
  const sessionBusy = createMemo(() => {
    const id = params.id
    if (!id) return false
    return sync.data.session_status?.[id]?.type === "busy"
  })
  createEffect((wasBusy: boolean | undefined) => {
    const busy = sessionBusy()
    if (wasBusy && !busy) void refetchFindings()
    return busy
  })

  /**
   * "Re-verificar" delega en el agente en vez del chequeo pasivo por HTTP: le
   * inserta el pedido en el chat con el contexto del hallazgo, y el agente
   * cierra el ciclo llamando a `finding_status`.
   */
  const requestAgentVerify = async (finding: Finding) => {
    const sessionID = params.id
    const model = local.model.current()
    const agent = local.agent.current()
    if (!sessionID || !finding.id || !model || !agent) {
      showToast({ title: language.t("findings.retest.agentFailed") })
      return false
    }

    const text = buildReverifyPrompt(finding, language.t)
    try {
      await sendFollowupDraft({
        client: sdk.client,
        sync,
        serverSync,
        draft: {
          sessionID,
          sessionDirectory: sdk.directory,
          prompt: [{ type: "text", content: text, start: 0, end: text.length }],
          context: [],
          agent: agent.name,
          model: { modelID: model.id, providerID: model.provider.id },
          variant: local.model.variant.current(),
        },
        optimisticBusy: true,
      })
      showToast({
        title: language.t("findings.retest.agentSent"),
        description: language.t("findings.retest.agentSentBody"),
      })
      return true
    } catch {
      showToast({ title: language.t("findings.retest.agentFailed") })
      return false
    }
  }

  const reviewOpen = createMemo(() => isDesktop() && view().reviewPanel.opened())
  const fileOpen = createMemo(() => isDesktop() && shown() && layout.fileTree.opened())
  const open = createMemo(() => reviewOpen() || fileOpen())
  const panelWidth = createMemo(() => {
    if (!open()) return "0px"
    if (props.compact()) return "min(420px, 100%)"
    if (reviewOpen()) return "auto"
    return `${layout.fileTree.width()}px`
  })
  const treeWidth = createMemo(() => (fileOpen() ? `${layout.fileTree.width()}px` : "0px"))

  const sessionFindings = createMemo(() => {
    const sessionID = params.id
    if (!sessionID) return []

    const parts = []
    const messages = sync.data.message[sessionID] ?? []
    for (const msg of messages) {
      parts.push(...normalizeToolParts(sync.data.part[msg.id] ?? []))
    }

    return selectSessionFindings(sessionID, apiFindings() ?? [], extractFindings(parts))
  })

  const cockpitFindings = createMemo<CockpitFinding[]>(() =>
    sessionFindings().map((f, i) => mapToCockpitFinding(f, i)),
  )

  const findingsCounts = createMemo(() => severityCounts(sessionFindings()))
  const findingsTotal = createMemo(() => sessionFindings().length)
  const hasFindings = createMemo(() => findingsTotal() > 0)

  const criticalCount = createMemo(() => findingsCounts().critical)


  const sessionWebSurface = createMemo(() => {
    const ids = familyIds()
    if (ids.length === 0) return undefined

    const parts = []

    for (const sid of ids) {
      const messages = sync.data.message[sid] ?? []
      for (const msg of messages) {
        parts.push(...normalizeToolParts(sync.data.part[msg.id] ?? []))
      }
    }

    return extractWebSurface(parts)
  })

  const hasWebSurface = createMemo(() => !!sessionWebSurface())
  // --- End Findings state ---

  // --- Topology state: available when network scan / LAN tools were executed
  // in this session's own live message history, OR reconciled from a peer
  // agent (e.g. security-ops) that ran the scan out-of-process and persisted
  // it as a tagged finding — see topologyPartsFromFindings for why the latter
  // is needed even though it's not a "child session" in the parentID sense. ---
  const sessionLanParts = createMemo(() => {
    const ids = familyIds()
    const reconciled = topologyPartsFromFindings(sessionFindings())
    if (ids.length === 0) return reconciled

    const messages: { id: string }[] = []
    for (const sid of ids) {
      messages.push(...(sync.data.message[sid] ?? []))
    }
    const live = extractLanPartsFromMessages(messages, sync.data.part as Record<string, unknown[] | undefined>)
    return [...reconciled, ...live]
  })

  const hasTopology = createMemo(() => hasTopologyData(sessionLanParts()))

  const diffs = createMemo(() => props.diffs().filter(renderDiff))
  const diffFiles = createMemo(() => diffs().map((d) => d.file))
  const kinds = createMemo(() => {
    const merge = (a: "add" | "del" | "mix" | undefined, b: "add" | "del" | "mix") => {
      if (!a) return b
      if (a === b) return a
      return "mix" as const
    }

    const normalize = (p: string) => p.replaceAll("\\\\", "/").replace(/\/+$/, "")

    const out = new Map<string, "add" | "del" | "mix">()
    for (const diff of diffs()) {
      const file = normalize(diff.file)
      const kind = diff.status === "added" ? "add" : diff.status === "deleted" ? "del" : "mix"

      out.set(file, kind)

      const parts = file.split("/")
      for (const [idx] of parts.slice(0, -1).entries()) {
        const dir = parts.slice(0, idx + 1).join("/")
        if (!dir) continue
        out.set(dir, merge(out.get(dir), kind))
      }
    }
    return out
  })

  const empty = (msg: string) => (
    <div class="h-full flex flex-col">
      <div class="h-6 shrink-0" aria-hidden />
      <div class="flex-1 pb-64 flex items-center justify-center text-center">
        <div class="text-12-regular text-text-secondary">{msg}</div>
      </div>
    </div>
  )

  const nofiles = createMemo(() => {
    const state = file.tree.state("")
    if (!state?.loaded) return false
    return file.tree.children("").length === 0
  })

  const normalizeTab = (tab: string) => {
    if (!tab.startsWith("file://")) return tab
    return file.tab(tab)
  }

  const openReviewPanel = () => {
    if (!view().reviewPanel.opened()) view().reviewPanel.open()
  }

  const openTab = createOpenSessionFileTab({
    normalizeTab,
    openTab: tabs().open,
    pathFromTab: file.pathFromTab,
    loadFile: file.load,
    openReviewPanel,
    setActive: tabs().setActive,
  })

  const tabState = createSessionTabs({
    tabs,
    pathFromTab: file.pathFromTab,
    normalizeTab,
    hasTopology,
  })
  const contextOpen = tabState.contextOpen
  const openedTabs = tabState.openedTabs
  const activeTab = tabState.activeTab
  const activeFileTab = tabState.activeFileTab

  const fileTreeTab = () => layout.fileTree.tab()

  const setFileTreeTabValue = (value: string) => {
    if (value !== "changes" && value !== "all") return
    layout.fileTree.setTab(value)
  }

  const [store, setStore] = createStore({
    activeDraggable: undefined as string | undefined,
  })

  const handleDragStart = (event: unknown) => {
    const id = getDraggableId(event)
    if (!id) return
    setStore("activeDraggable", id)
  }

  const handleDragOver = (event: DragEvent) => {
    const { draggable, droppable } = event
    if (!draggable || !droppable) return

    const currentTabs = tabs().all()
    const toIndex = getTabReorderIndex(currentTabs, draggable.id.toString(), droppable.id.toString())
    if (toIndex === undefined) return
    tabs().move(draggable.id.toString(), toIndex)
  }

  const handleDragEnd = () => {
    setStore("activeDraggable", undefined)
  }

  createEffect(() => {
    if (!file.ready()) return

    setSessionHandoff(sessionKey(), {
      files: tabs()
        .all()
        .reduce<Record<string, SelectedLineRange | null>>((acc, tab) => {
          const path = file.pathFromTab(tab)
          if (!path) return acc

          const selected = file.selectedLines(path)
          acc[path] =
            selected && typeof selected === "object" && "start" in selected && "end" in selected
              ? (selected as SelectedLineRange)
              : null

          return acc
        }, {}),
    })
  })

  return (
    <Show when={isDesktop() && !!params.id}>
      <aside
        id="review-panel"
        aria-label={language.t("session.panel.reviewAndFiles")}
        aria-hidden={!open()}
        inert={!open()}
        class="relative min-w-[280px] h-full flex shrink-0 overflow-hidden bg-bg-surface border border-border-weaker-base/80 rounded-[4px] shadow-xs"
        classList={{
          "pointer-events-none": !open(),
          "absolute right-0 top-0 z-20 max-w-full !min-w-0 shadow-lg": open() && props.compact(),
          "!min-w-0": !open(),
          "transition-[width] duration-[240ms] ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none":
            !props.size.active() && !props.reviewSnap,
          "flex-1": reviewOpen() && !props.compact(),
        }}
        style={{
          width: panelWidth(),
          "min-width": !open() ? "0px" : props.compact() ? "min(280px, 100%)" : "280px",
        }}
      >
        <Show when={open()}>
          <div class="size-full flex">
            <div
              aria-hidden={!reviewOpen()}
              inert={!reviewOpen()}
              class="relative min-w-0 h-full flex-1 overflow-hidden bg-bg-surface"
            >
              <div class="session-review-shell relative size-full min-w-0 h-full bg-bg-surface flex flex-col">
                <DragDropProvider
                  onDragStart={handleDragStart}
                  onDragEnd={handleDragEnd}
                  onDragOver={handleDragOver}
                  collisionDetector={closestCenter}
                >
                  <DragDropSensors />
                  <ConstrainDragYAxis />
                  <Tabs value={activeTab()} onChange={openTab} variant="dossier">
                    <div class="sticky top-0 z-10 flex h-[38px] min-w-0 shrink-0 items-center justify-between border-b border-border-weaker-base/70 bg-bg-surface px-1">
                      <Tabs.List
                        class="min-w-0 flex-1"
                        ref={(el: HTMLDivElement) => {
                          const stop = createFileTabListSync({ el, contextOpen })
                          onCleanup(stop)
                        }}
                      >
                        {/* Findings Native Tab */}
                        <Show when={params.id}>
                          <Tabs.Trigger
                            value="findings"
                            aria-label={language.t("session.panel.findings")}
                            title={language.t("session.panel.findings")}
                          >
                            <div class="flex items-center gap-1.5">
                              <Icon name="shield" class="shrink-0" />
                              <span class="session-review-tab-label">{language.t("session.panel.findings")}</span>
                              <Show when={hasFindings()}>
                                <span class="tabular-nums text-10-mono font-medium text-text-tertiary">{findingsTotal()}</span>
                              </Show>
                              <Show when={criticalCount() > 0}>
                                <span class="inline-flex items-center justify-center h-4 min-w-4 rounded-sm border border-severity-border-critical bg-severity-bg-critical px-1 text-10-mono font-bold text-severity-fg-critical tabular-nums">
                                  {criticalCount()}
                                </span>
                              </Show>
                            </div>
                          </Tabs.Trigger>
                        </Show>

                        {/* Compliance Native Tab */}
                        <Show when={params.id}>
                          <Tabs.Trigger
                            value="compliance"
                            aria-label={language.t("session.panel.compliance")}
                            title={language.t("session.panel.compliance")}
                          >
                            <div class="flex items-center gap-1.5">
                              <Icon name="checklist" class="shrink-0" />
                              <span class="session-review-tab-label">{language.t("session.panel.compliance")}</span>
                            </div>
                          </Tabs.Trigger>
                        </Show>

                        {/* Report Native Tab */}
                        <Show when={params.id}>
                          <Tabs.Trigger
                            value="report"
                            aria-label={language.t("session.panel.report")}
                            title={language.t("session.panel.report")}
                          >
                            <div class="flex items-center gap-1.5">
                              <Icon name="open-file" class="shrink-0" />
                              <span class="session-review-tab-label">{language.t("session.panel.report")}</span>
                            </div>
                          </Tabs.Trigger>
                        </Show>

                        {/* Traffic Native Tab */}
                        <Show when={params.id}>
                          <Tabs.Trigger
                            value="traffic"
                            aria-label={language.t("session.panel.traffic")}
                            title={language.t("session.panel.traffic")}
                          >
                            <div class="flex items-center gap-1.5">
                              <Icon name="globe" class="shrink-0" />
                              <span class="session-review-tab-label">{language.t("session.panel.traffic")}</span>
                            </div>
                          </Tabs.Trigger>
                        </Show>

                        {/* Topology Native Tab */}
                        <Show when={params.id && hasTopology()}>
                          <Tabs.Trigger value="topology">
                            <div class="flex items-center gap-1.5">
                              <Icon name="server" class="shrink-0" />
                              <span>{language.t("session.panel.topology")}</span>
                              <Show when={sessionFindings().length > 0}>
                                <span class="size-1.5 rounded-full bg-severity-fg-critical" title={language.t("session.panel.findings.title")} />
                              </Show>
                            </div>
                          </Tabs.Trigger>
                        </Show>

                        <Show when={contextOpen()}>
                          <Tabs.Trigger
                            value="context"
                            onMiddleClick={() => tabs().close("context")}
                          >
                            <div class="flex items-center gap-1.5">
                              <Icon name="context" class="shrink-0" />
                              <div>{language.t("session.tab.context")}</div>
                            </div>
                          </Tabs.Trigger>
                        </Show>
                        <SortableProvider ids={openedTabs()}>
                          <For each={openedTabs()}>{(tab) => <SortableTab tab={tab} onTabClose={tabs().close} />}</For>
                        </SortableProvider>
                      </Tabs.List>
                      <Show when={props.compact()}>
                        <button
                          type="button"
                          class="inline-flex size-7 shrink-0 items-center justify-center text-text-tertiary hover:text-text-primary focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent"
                          aria-label={language.t("session.panel.hide")}
                          title={language.t("session.panel.hide")}
                          onClick={() => {
                            view().reviewPanel.close()
                            layout.fileTree.close()
                          }}
                        >
                          <Icon name="close" class="size-3.5" />
                        </button>
                      </Show>
                    </div>

                    {/* Findings Native Tab Content */}
                    <Show when={params.id}>
                      <Tabs.Content value="findings" class="flex flex-col h-full overflow-hidden contain-strict">
                        <Show when={activeTab() === "findings"}>
                          <div class="relative h-full overflow-hidden flex flex-col">
                            <FindingImportPanel
                              sessionID={params.id ?? ""}
                              onImported={() => void refetchFindings()}
                            />
                            {/* Cabecera y tabla Master-Detail pericial cockpit Mosby Files */}
                            <div class="flex-1 min-h-0 overflow-hidden flex flex-col">
                              <Show
                                when={hasFindings() || hasWebSurface()}
                                fallback={
                                  <div class="flex flex-1 flex-col h-full items-center justify-center gap-2 p-8 text-center">
                                    <div class="flex h-12 w-12 items-center justify-center rounded-sm bg-bg-surface border border-border-weaker-base text-text-secondary mb-1">
                                      <Icon name="shield" class="w-6 h-6 text-text-secondary" />
                                    </div>
                                    <div class="text-sm font-semibold text-text-primary">{language.t("session.panel.findings.empty")}</div>
                                    <div class="text-xs text-text-secondary max-w-80 leading-relaxed">
                                      {language.t("session.panel.findings.empty.body")}
                                    </div>
                                  </div>
                                }
                              >
                                <FindingsTable
                                  findings={sessionFindings()}
                                  sessionID={params.id ?? ""}
                                  surface={sessionWebSurface()}
                                  onAgentVerify={requestAgentVerify}
                                />
                              </Show>
                            </div>
                          </div>
                        </Show>
                      </Tabs.Content>
                    </Show>

                    {/* Compliance Native Tab Content */}
                    <Show when={params.id}>
                      <Tabs.Content value="compliance" class="flex flex-col h-full overflow-hidden contain-strict">
                        <Show when={activeTab() === "compliance"}>
                          <div class="relative h-full overflow-hidden flex flex-col min-h-0">
                            <ComplianceCockpitTab
                              findings={cockpitFindings()}
                              onJumpToFinding={(_shortId) => {
                                openTab("findings")
                              }}
                            />
                          </div>
                        </Show>
                      </Tabs.Content>
                    </Show>

                    {/* Report Native Tab Content */}
                    <Show when={params.id}>
                      <Tabs.Content value="report" class="flex flex-col h-full overflow-hidden contain-strict">
                        <Show when={activeTab() === "report"}>
                          <div class="relative flex h-full flex-col overflow-hidden min-h-0">
                            <ExecutiveReportCockpitTab
                              findings={cockpitFindings()}
                              onInspectFinding={(_id) => {
                                openTab("findings")
                              }}
                              targetScope={targetDirFromParams(params) || sessionWebSurface()?.target || "Auditoría"}
                            />
                          </div>
                        </Show>
                      </Tabs.Content>
                    </Show>

                    {/* Traffic Native Tab Content */}
                    <Show when={params.id}>
                      <Tabs.Content value="traffic" class="flex flex-col h-full overflow-hidden contain-strict">
                        <Show when={activeTab() === "traffic"}>
                          <div class="relative h-full overflow-hidden flex flex-col">
                            <TrafficPanel sessionId={params.id!} />
                          </div>
                        </Show>
                      </Tabs.Content>
                    </Show>

                    {/* Topology Native Tab Content */}
                    <Show when={params.id && hasTopology()}>
                      <Tabs.Content value="topology" class="flex flex-col h-full overflow-hidden contain-strict">
                        <Show when={activeTab() === "topology"}>
                          <div class="relative h-full overflow-hidden flex flex-col">
                            <TopologyPanel
                              sessionId={params.id!}
                              findings={sessionFindings()}
                            />
                          </div>
                        </Show>
                      </Tabs.Content>
                    </Show>

                    <Tabs.Content value="empty" class="flex flex-col h-full overflow-hidden contain-strict">
                      <Show when={activeTab() === "empty"}>
                        <div class="relative pt-2 flex-1 min-h-0 overflow-hidden">
                          <div class="h-full px-6 pb-42 -mt-4 flex flex-col items-center justify-center text-center gap-4">
                            <div class="opacity-20"><ThinkingOrb state="listening" size={48} /></div>
                            <Show
                              when={hasFindings()}
                              fallback={
                                <div class="text-14-regular text-text-secondary max-w-56">
                                  {language.t("session.panel.empty")}
                                </div>
                              }
                            >
                              <div class="flex flex-col items-center gap-3">
                                <div class="text-14-medium text-text-primary">
                                  {language.t(
                                    findingsTotal() === 1 ? "session.panel.findings.count.one" : "session.panel.findings.count.other",
                                    { count: findingsTotal() },
                                  )}
                                </div>
                                <div class="flex items-center gap-1.5 flex-wrap justify-center">
                                  <Show when={criticalCount() > 0}>
                                    <span class="inline-flex items-center gap-1 rounded-sm border border-severity-border-critical bg-severity-bg-critical px-2 py-0.5 text-10-mono font-bold text-severity-fg-critical">
                                      {criticalCount()} {language.t(SEVERITY_LABELS.critical).toUpperCase()}
                                    </span>
                                  </Show>
                                  <Show when={findingsCounts().high > 0}>
                                    <span class="inline-flex items-center gap-1 rounded-sm border border-severity-border-high bg-severity-bg-high px-2 py-0.5 text-10-mono font-bold text-severity-fg-high">
                                      {findingsCounts().high} {language.t(SEVERITY_LABELS.high).toUpperCase()}
                                    </span>
                                  </Show>
                                  <Show when={findingsCounts().medium > 0}>
                                    <span class="inline-flex items-center gap-1 rounded-sm border border-severity-border-medium bg-severity-bg-medium px-2 py-0.5 text-10-mono font-bold text-severity-fg-medium">
                                      {findingsCounts().medium} {language.t(SEVERITY_LABELS.medium).toUpperCase()}
                                    </span>
                                  </Show>
                                  <Show when={findingsCounts().low > 0}>
                                    <span class="inline-flex items-center gap-1 rounded-sm border border-severity-border-low bg-severity-bg-low px-2 py-0.5 text-10-mono font-bold text-severity-fg-low">
                                      {findingsCounts().low} {language.t(SEVERITY_LABELS.low).toUpperCase()}
                                    </span>
                                  </Show>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => openTab("findings")}
                                  class="mt-2 inline-flex items-center gap-2 rounded-sm border border-border-weaker-base bg-bg-elevated px-4 py-2 text-13-medium text-accent transition-colors hover:bg-bg-elevated cursor-pointer"
                                >
                                  <Icon name="shield" size="small" />
                                  <span>{language.t("session.panel.viewFindings")}</span>
                                </button>
                              </div>
                            </Show>
                          </div>
                        </div>
                      </Show>
                    </Tabs.Content>

                    <Show when={contextOpen()}>
                      <Tabs.Content value="context" class="flex flex-col h-full overflow-hidden contain-strict">
                        <Show when={activeTab() === "context"}>
                          <div class="relative h-full overflow-hidden flex flex-col">
                            <SessionContextTab />
                          </div>
                        </Show>
                      </Tabs.Content>
                    </Show>

                    <Tabs.Content value="review" class="flex flex-col h-full overflow-hidden contain-strict">
                      <Show when={activeTab() === "review"}>
                        <div class="relative h-full overflow-hidden flex flex-col">
                          {props.reviewPanel()}
                        </div>
                      </Show>
                    </Tabs.Content>

                    <Show when={activeFileTab()} keyed>
                      {(tab) => <FileTabContent tab={tab} />}
                    </Show>
                  </Tabs>

                  <DragOverlay>
                    <Show when={store.activeDraggable} keyed>
                      {(tab) => {
                        const path = file.pathFromTab(tab)
                        return (
                          <div data-component="tabs-drag-preview">
                            <Show when={path}>{(p) => <FileVisual active path={p()} />}</Show>
                          </div>
                        )
                      }}
                    </Show>
                  </DragOverlay>
                </DragDropProvider>
              </div>
            </div>

            <Show when={shown()}>
              <div
                id="file-tree-panel"
                aria-hidden={!fileOpen()}
                inert={!fileOpen()}
                class="relative min-w-0 h-full shrink-0 overflow-hidden"
                classList={{
                  "pointer-events-none": !fileOpen(),
                  "transition-[width] duration-200 ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none":
                    !props.size.active(),
                }}
                style={{ width: treeWidth() }}
              >
                <div
                  class="h-full flex flex-col overflow-hidden group/filetree"
                  classList={{ "border-l border-border-weaker-base": reviewOpen() }}
                >
                  <Tabs
                    variant="pill"
                    value={fileTreeTab()}
                    onChange={setFileTreeTabValue}
                    class="h-full flex flex-col"
                    data-scope="filetree"
                  >
                    <div class="p-2 border-b border-border-weaker-base shrink-0">
                      <Tabs.List class="w-full flex">
                        <Tabs.Trigger value="changes" class="flex-1" classes={{ button: "w-full" }}>
                          {props.reviewCount()}{" "}
                          {language.t(
                            props.reviewCount() === 1 ? "session.review.change.one" : "session.review.change.other",
                          )}
                        </Tabs.Trigger>
                        <Tabs.Trigger value="all" class="flex-1" classes={{ button: "w-full" }}>
                          {language.t("session.files.all")}
                        </Tabs.Trigger>
                      </Tabs.List>
                    </div>
                    <Tabs.Content value="changes" class="bg-bg-elevated px-3 py-0">
                      <Switch>
                        <Match when={props.hasReview() || !props.diffsReady()}>
                          <Show
                            when={props.diffsReady()}
                            fallback={
                              <div class="px-2 py-2 text-12-regular text-text-secondary">
                                {language.t("common.loading")}
                                {language.t("common.loading.ellipsis")}
                              </div>
                            }
                          >
                            <FileTree
                              path=""
                              class="pt-3"
                              allowed={diffFiles()}
                              kinds={kinds()}
                              draggable={false}
                              active={props.activeDiff}
                              onFileClick={(node) => props.focusReviewDiff(node.path)}
                            />
                          </Show>
                        </Match>
                      </Switch>
                    </Tabs.Content>
                    <Tabs.Content value="all" class="bg-bg-elevated px-3 py-0">
                      <Switch>
                        <Match when={nofiles()}>{empty(language.t("session.files.empty"))}</Match>
                        <Match when={true}>
                          <FileTree
                            path=""
                            class="pt-3"
                            modified={diffFiles()}
                            kinds={kinds()}
                            onFileClick={(node) => openTab(file.tab(node.path))}
                          />
                        </Match>
                      </Switch>
                    </Tabs.Content>
                  </Tabs>
                </div>
                <Show when={fileOpen()}>
                  <div onPointerDown={() => props.size.start()}>
                    <ResizeHandle
                      direction="horizontal"
                      edge="start"
                      size={layout.fileTree.width()}
                      min={200}
                      max={480}
                      onResize={(width) => {
                        props.size.touch()
                        layout.fileTree.resize(width)
                      }}
                    />
                  </div>
                </Show>
              </div>
            </Show>
          </div>
        </Show>
      </aside>
    </Show>
  )
}

