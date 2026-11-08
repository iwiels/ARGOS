import type { UserMessage } from "@argos/sdk/client"
import { useDialog } from "@argos/ui/context/dialog"
import { useMutation } from "@tanstack/solid-query"
import {
  batch,
  onCleanup,
  Show,
  Match,
  Switch,
  createMemo,
  createResource,
  createEffect,
  createComputed,
  on,
  onMount,
  untrack,
} from "solid-js"
import { makeEventListener } from "@solid-primitives/event-listener"
import { createMediaQuery } from "@solid-primitives/media"
import { createResizeObserver } from "@solid-primitives/resize-observer"
import { useLocal } from "@/context/local"
import { useFile } from "@/context/file"
import { createStore } from "solid-js/store"
import { ResizeHandle } from "@argos/ui/resize-handle"
import { Select } from "@argos/ui/select"
import { Tabs } from "@argos/ui/tabs"
import { createAutoScroll } from "@argos/ui/hooks"
import { Icon } from "@argos/ui/icon"
import { Spinner } from "@argos/ui/spinner"
import { showToast } from "@/utils/toast"
import { useLocation, useSearchParams } from "@solidjs/router"
import { NewSessionDesignView, SessionHeader } from "@/components/session"
import { useComments } from "@/context/comments"
import { useServerSync } from "@/context/server-sync"
import { useLanguage } from "@/context/language"
import { useLayout } from "@/context/layout"
import { usePlatform } from "@/context/platform"
import { usePrompt } from "@/context/prompt"
import { useSDK } from "@/context/sdk"
import { useServerSDK } from "@/context/server-sdk"
import { useSettings } from "@/context/settings"
import { useSync } from "@/context/sync"
import { useTerminal } from "@/context/terminal"
import { type FollowupDraft, sendFollowupDraft } from "@/components/prompt-input/submit"
import { createSessionComposerState, SessionComposerRegion } from "@/pages/session/composer"
import { createSessionHistoryLoader } from "@/pages/session/create-session-history-loader"
import {
  calculateSessionPanelSizing,
  createOpenReviewFile,
  createSessionTabs,
  createSizing,
  focusTerminalById,
  shouldFocusTerminalOnKeyDown,
} from "@/pages/session/helpers"
import { MessageTimeline } from "@/pages/session/message-timeline"
import { type DiffStyle, SessionReviewTab, type SessionReviewTabProps } from "@/pages/session/review-tab"
import { useSessionLayout } from "@/pages/session/session-layout"
import { useServer } from "@/context/server"
import { syncSessionModel } from "@/pages/session/session-model-helpers"
import { SessionSidePanel } from "@/pages/session/session-side-panel"
import { TerminalPanel } from "@/pages/session/terminal-panel"
import { useSessionCommands } from "@/pages/session/use-session-commands"
import { useSessionHashScroll } from "@/pages/session/use-session-hash-scroll"
import { shouldUseV2NewSessionPage } from "@/pages/session/new-session-layout"
import { Identifier } from "@/utils/id"
import { Persist, persisted } from "@/utils/persist"
import { extractPromptFromParts } from "@/utils/prompt"
import { same } from "@/utils/same"
import { formatServerError } from "@/utils/server-errors"
import { useUsageExceededDialogs } from "./session/usage-exceeded-dialogs"
import { useCommentContextActions } from "./session/use-comment-context-actions"
import { useReviewDiffFocus } from "./session/use-review-diff-focus"
import { useSessionDataRefresh } from "./session/use-session-data-refresh"
import { useSessionVcsReview, type ChangeMode } from "./session/use-session-vcs-review"

const emptyUserMessages: UserMessage[] = []
type SessionExecutionRun = { id: string; status: "running" | "completed" | "interrupted" | "failed"; error?: string }
type SessionExecutionState = { runs: SessionExecutionRun[]; error?: string }
type FollowupItem = FollowupDraft & { id: string }
type FollowupEdit = Pick<FollowupItem, "id" | "prompt" | "context">
const emptyFollowups: FollowupItem[] = []

export default function Page() {
  const serverSync = useServerSync()
  const layout = useLayout()
  const local = useLocal()
  const file = useFile()
  const sync = useSync()
  const dialog = useDialog()
  const language = useLanguage()
  const sdk = useSDK()
  const serverSDK = useServerSDK()
  const settings = useSettings()
  const prompt = usePrompt()
  const comments = useComments()
  const terminal = useTerminal()
  const server = useServer()
  const [searchParams, setSearchParams] = useSearchParams<{ prompt?: string }>()
  const location = useLocation()
  const { params, sessionKey, workspaceKey, tabs, view } = useSessionLayout()

  createEffect(() => {
    if (!prompt.ready()) return
    untrack(() => {
      if (params.id) return
      const text = searchParams.prompt
      if (!text) return
      prompt.set([{ type: "text", content: text, start: 0, end: text.length }], text.length)
      setSearchParams({ ...searchParams, prompt: undefined })
    })
  })

  const [ui, setUi] = createStore({
    pendingMessage: undefined as string | undefined,
    resumeRunning: false,
    resumeAcknowledgedRunID: undefined as string | undefined,
    reviewSnap: false,
    sessionSplitWidth: 0,
    scrollGesture: 0,
    scroll: {
      overflow: false,
      bottom: true,
      jump: false,
    },
  })

  const composer = createSessionComposerState()

  const workspaceTabs = createMemo(() => layout.tabs(workspaceKey))

  createEffect(
    on(
      () => params.id,
      (id, prev) => {
        if (!id) return
        if (prev) return

        const pending = layout.handoff.tabs()
        if (!pending) return
        if (Date.now() - pending.at > 60_000) {
          layout.handoff.clearTabs()
          return
        }
        if (pending.scope !== server.scope()) return

        if (pending.id !== id) return
        layout.handoff.clearTabs()
        if (pending.dir !== (params.dir ?? "")) return

        const from = workspaceTabs().tabs()
        if (from.all.length === 0 && !from.active) return

        const current = tabs().tabs()
        if (current.all.length > 0 || current.active) return

        const all = normalizeTabs(from.all)
        const active = from.active ? normalizeTab(from.active) : undefined
        tabs().setAll(all)
        tabs().setActive(active && all.includes(active) ? active : all[0])

        workspaceTabs().setAll([])
        workspaceTabs().setActive(undefined)
      },
      { defer: true },
    ),
  )

  const platform = usePlatform()
  const isDesktopQuery = createMediaQuery("(min-width: 600px)")
  const isDesktop = createMemo(() => platform.platform === "desktop" || isDesktopQuery())
  const size = createSizing()
  const isV2NewSessionPage = () => shouldUseV2NewSessionPage({ sessionID: params.id })
  const desktopReviewOpen = createMemo(() => isDesktop() && view().reviewPanel.opened() && !isV2NewSessionPage())
  const desktopFileTreeOpen = createMemo(() => isDesktop() && layout.fileTree.opened() && !isV2NewSessionPage())
  const desktopSidePanelOpen = createMemo(() => desktopReviewOpen() || desktopFileTreeOpen())
  let sessionSplitContainer: HTMLDivElement | undefined
  const sessionSplitSizing = createMemo(() => {
    const availableWidth =
      ui.sessionSplitWidth ||
      sessionSplitContainer?.clientWidth ||
      (typeof window === "undefined"
        ? layout.session.width() + 688
        : Math.max(0, window.innerWidth - layout.sidebar.width() - 32))
    return calculateSessionPanelSizing(availableWidth, layout.session.width())
  })
  const compactSessionLayout = createMemo(() => sessionSplitSizing().mode === "overlay")
  const sessionWidthClamped = createMemo(() => {
    return sessionSplitSizing().chatWidth
  })
  createResizeObserver(() => sessionSplitContainer, ({ width }) => {
    const next = Math.floor(width)
    if (next > 0 && next !== ui.sessionSplitWidth) setUi("sessionSplitWidth", next)
  })
  const sessionPanelWidth = createMemo(() => {
    if (!desktopSidePanelOpen()) return "100%"
    if (compactSessionLayout()) return "100%"
    if (desktopReviewOpen()) return `${sessionWidthClamped()}px`
    return `calc(100% - ${Math.max(280, layout.fileTree.width()) + 8}px)`
  })
  const centered = createMemo(() => isDesktop() && !desktopReviewOpen())

  function normalizeTab(tab: string) {
    if (!tab.startsWith("file://")) return tab
    return file.tab(tab)
  }

  function normalizeTabs(list: string[]) {
    const seen = new Set<string>()
    const next: string[] = []
    for (const item of list) {
      const value = normalizeTab(item)
      if (seen.has(value)) continue
      seen.add(value)
      next.push(value)
    }
    return next
  }

  const openReviewPanel = () => {
    if (!view().reviewPanel.opened()) view().reviewPanel.open()
  }

  const info = createMemo(() => (params.id ? sync.session.get(params.id) : undefined))
  const [executions, { refetch: refetchExecutions }] = createResource(
    () => params.id,
    async (sessionID) => {
      if (!sessionID) return { runs: [] } satisfies SessionExecutionState
      try {
        const response = await serverSDK.request(
          `/api/session/${encodeURIComponent(sessionID)}/runs`,
          {},
          sdk.directory,
        )
        if (!response.ok) {
          const details = (await response.text().catch(() => "")).trim().slice(0, 500)
          return {
            runs: [],
            error: details || `HTTP ${response.status}`,
          } satisfies SessionExecutionState
        }
        const result = (await response.json()) as { data?: SessionExecutionRun[] }
        return { runs: result.data ?? [] } satisfies SessionExecutionState
      } catch (error) {
        return {
          runs: [],
          error: formatServerError(error, language.t, language.t("common.requestFailed")),
        } satisfies SessionExecutionState
      }
    },
  )
  const refreshExecutions = () => Promise.resolve(refetchExecutions()).catch(() => undefined)
  const interruptedRun = createMemo(() => {
    const latest = executions()?.runs[0]
    return latest?.status === "interrupted" ? latest : undefined
  })
  const isChildSession = createMemo(() => !!info()?.parentID)
  const canReview = createMemo(() => !!sync.project)
  const reviewTab = createMemo(() => isDesktop())
  const tabState = createSessionTabs({
    tabs,
    pathFromTab: file.pathFromTab,
    normalizeTab,
    review: reviewTab,
    hasReview: canReview,
  })
  const activeTab = tabState.activeTab
  const activeFileTab = tabState.activeFileTab
  const revertMessageID = createMemo(() => info()?.revert?.messageID)
  const messages = createMemo(() => (params.id ? (sync.data.message[params.id] ?? []) : []))
  const messagesReady = createMemo(() => {
    const id = params.id
    if (!id) return true
    return sync.data.message[id] !== undefined
  })
  const historyMore = createMemo(() => {
    const id = params.id
    if (!id) return false
    return sync.session.history.more(id)
  })
  const historyLoading = createMemo(() => {
    const id = params.id
    if (!id) return false
    return sync.session.history.loading(id)
  })
  const userMessages = createMemo(
    () => messages().filter((m) => m.role === "user"),
    emptyUserMessages,
    { equals: same },
  )
  const visibleUserMessages = createMemo(
    () => {
      const revert = revertMessageID()
      if (!revert) return userMessages()
      return userMessages().filter((m) => m.id < revert)
    },
    emptyUserMessages,
    {
      equals: same,
    },
  )
  const lastUserMessage = createMemo(() => visibleUserMessages().at(-1))

  createEffect(() => {
    const tab = activeFileTab()
    if (!tab) return

    const path = file.pathFromTab(tab)
    if (path) void file.load(path)
  })

  createEffect(
    on(
      () => lastUserMessage()?.id,
      () => {
        const msg = lastUserMessage()
        if (!msg) return
        syncSessionModel(local, msg)
      },
    ),
  )

  createEffect(
    on(
      () => ({ dir: params.dir, id: params.id }),
      (next, prev) => {
        if (!prev) return
        if (next.dir === prev.dir && next.id === prev.id) return
        if (prev.id && !next.id) local.session.reset()
      },
      { defer: true },
    ),
  )

  const [store, setStore] = createStore({
    messageId: undefined as string | undefined,
    mobileTab: "session" as "session" | "changes",
    changes: "git" as ChangeMode,
    newSessionWorktree: "main",
    deferRender: false,
  })

  const [followup, setFollowup] = persisted(
    Persist.serverWorkspace(serverSDK.scope, sdk.directory, "followup", ["followup.v1"]),
    createStore<{
      items: Record<string, FollowupItem[] | undefined>
      failed: Record<string, string | undefined>
      paused: Record<string, boolean | undefined>
      edit: Record<string, FollowupEdit | undefined>
    }>({
      items: {},
      failed: {},
      paused: {},
      edit: {},
    }),
  )

  createComputed((prev) => {
    const key = sessionKey()
    if (key !== prev) {
      setStore("deferRender", true)
      requestAnimationFrame(() => {
        setTimeout(() => setStore("deferRender", false), 0)
      })
    }
    return key
  }, sessionKey())

  let reviewFrame: number | undefined
  let diffFrame: number | undefined
  let diffTimer: number | undefined

  createComputed((prev) => {
    const open = desktopReviewOpen()
    if (prev === undefined || prev === open) return open

    if (reviewFrame !== undefined) cancelAnimationFrame(reviewFrame)
    setUi("reviewSnap", true)
    reviewFrame = requestAnimationFrame(() => {
      reviewFrame = undefined
      setUi("reviewSnap", false)
    })
    return open
  }, desktopReviewOpen())

  const mobileChanges = createMemo(() => !isDesktop() && store.mobileTab === "changes")
  const wantsReview = createMemo(() =>
    isDesktop()
      ? desktopFileTreeOpen() || (desktopReviewOpen() && activeTab() === "review")
      : store.mobileTab === "changes",
  )
  const { changesOptions, reviewDiffs, reviewCount, hasReview, reviewReady, refreshVcs } = useSessionVcsReview({
    changes: () => store.changes,
    wantsReview,
    lastUserMessage,
  })
  const { tree, setTree, focusReviewDiff } = useReviewDiffFocus({
    sessionKey,
    reviewReady,
    openPanel: openReviewPanel,
    openPath: (path) => view().review.openPath(path),
    setScrollReview: (pos) => view().setScroll("review", pos),
  })

  const newSessionWorktree = createMemo(() => {
    if (store.newSessionWorktree === "create") return "create"
    const project = sync.project
    if (project && sdk.directory !== project.worktree) return sdk.directory
    return "main"
  })

  const setActiveMessage = (message: UserMessage | undefined) => {
    messageMark = scrollMark
    setStore("messageId", message?.id)
  }

  const anchor = (id: string) => `message-${id}`

  const cursor = () => {
    const root = scroller
    if (!root) return store.messageId

    const box = root.getBoundingClientRect()
    const line = box.top + 100
    const list = [...root.querySelectorAll<HTMLElement>("[data-message-id]")]
      .map((el) => {
        const id = el.dataset.messageId
        if (!id) return

        const rect = el.getBoundingClientRect()
        return { id, top: rect.top, bottom: rect.bottom }
      })
      .filter((item): item is { id: string; top: number; bottom: number } => !!item)

    const shown = list.filter((item) => item.bottom > box.top && item.top < box.bottom)
    const hit = shown.find((item) => item.top <= line && item.bottom >= line)
    if (hit) return hit.id

    const near = [...shown].sort((a, b) => {
      const da = Math.abs(a.top - line)
      const db = Math.abs(b.top - line)
      if (da !== db) return da - db
      return a.top - b.top
    })[0]
    if (near) return near.id

    return list.filter((item) => item.top <= line).at(-1)?.id ?? list[0]?.id ?? store.messageId
  }

  function navigateMessageByOffset(offset: number) {
    const msgs = visibleUserMessages()
    if (msgs.length === 0) return

    const current = store.messageId && messageMark === scrollMark ? store.messageId : cursor()
    const base = current ? msgs.findIndex((m) => m.id === current) : msgs.length
    const currentIndex = base === -1 ? msgs.length : base
    const targetIndex = currentIndex + offset
    if (targetIndex < 0 || targetIndex > msgs.length) return

    if (targetIndex === msgs.length) {
      resumeScroll()
      return
    }

    autoScroll.pause()
    scrollToMessage(msgs[targetIndex], "auto")
  }

  let inputRef!: HTMLDivElement
  let promptDock: HTMLDivElement | undefined
  let dockHeight = 0
  let scroller: HTMLDivElement | undefined
  let content: HTMLDivElement | undefined
  let revealMessage = (_id: string) => {}
  let scrollMark = 0
  let messageMark = 0

  const scrollGestureWindowMs = 250

  const markScrollGesture = (target?: EventTarget | null) => {
    const root = scroller
    if (!root) return

    const el = target instanceof Element ? target : undefined
    const nested = el?.closest("[data-scrollable]")
    if (nested && nested !== root) return

    setUi("scrollGesture", Date.now())
  }

  const hasScrollGesture = () => Date.now() - ui.scrollGesture < scrollGestureWindowMs

  const { sessionSync } = useSessionDataRefresh({
    sessionID: () => params.id,
    blocked: () => composer.blocked(),
  })

  createEffect(
    on(
      () => visibleUserMessages().at(-1)?.id,
      (lastId, prevLastId) => {
        if (lastId && prevLastId && lastId > prevLastId) {
          setStore("messageId", undefined)
        }
      },
      { defer: true },
    ),
  )

  createEffect(
    on(
      sessionKey,
      () => {
        setStore("messageId", undefined)
        setStore("changes", "git")
        setUi("pendingMessage", undefined)
      },
      { defer: true },
    ),
  )

  createEffect(
    on(
      () => params.dir,
      (dir) => {
        if (!dir) return
        setStore("newSessionWorktree", "main")
      },
      { defer: true },
    ),
  )

  const { addCommentToContext, updateCommentInContext, removeCommentFromContext, reviewCommentActions } =
    useCommentContextActions()

  const isEditableTarget = (target: EventTarget | null | undefined) => {
    if (!(target instanceof HTMLElement)) return false
    return /^(INPUT|TEXTAREA|SELECT|BUTTON)$/.test(target.tagName) || target.isContentEditable
  }

  const deepActiveElement = () => {
    let current: Element | null = document.activeElement
    while (current instanceof HTMLElement && current.shadowRoot?.activeElement) {
      current = current.shadowRoot.activeElement
    }
    return current instanceof HTMLElement ? current : undefined
  }

  const handleKeyDown = (event: KeyboardEvent) => {
    const path = event.composedPath()
    const target = path.find((item): item is HTMLElement => item instanceof HTMLElement)
    const activeElement = deepActiveElement()

    const protectedTarget = path.some(
      (item) => item instanceof HTMLElement && item.closest("[data-prevent-autofocus]") !== null,
    )
    if (protectedTarget || isEditableTarget(target)) return

    if (activeElement) {
      const isProtected = activeElement.closest("[data-prevent-autofocus]")
      const isInput = isEditableTarget(activeElement)
      if (isProtected || isInput) return
    }
    if (dialog.active) return

    if (activeElement === inputRef) {
      if (event.key === "Escape") inputRef?.blur()
      return
    }

    // Prefer the open terminal over the composer when it can take focus
    if (view().terminal.opened()) {
      const id = terminal.active()
      if (id && shouldFocusTerminalOnKeyDown(event) && focusTerminalById(id)) return
    }

    // Only treat explicit scroll keys as potential "user scroll" gestures.
    if (event.key === "PageUp" || event.key === "PageDown" || event.key === "Home" || event.key === "End") {
      markScrollGesture()
      return
    }

    if (event.key.length === 1 && event.key !== "Unidentified" && !(event.ctrlKey || event.metaKey)) {
      if (composer.blocked() || isChildSession()) return
      inputRef?.focus()
    }
  }

  createEffect(() => {
    const list = changesOptions()
    if (list.includes(store.changes)) return
    const next = list[0]
    if (!next) return
    setStore("changes", next)
  })

  createEffect(
    on(
      () => sync.data.session_status[params.id ?? ""]?.type,
      (next, prev) => {
        if (next !== "idle" || prev === undefined || prev === "idle") return
        refreshVcs()
        void refreshExecutions()
      },
      { defer: true },
    ),
  )

  const fileTreeTab = () => layout.fileTree.tab()
  const setFileTreeTab = (value: "changes" | "all") => layout.fileTree.setTab(value)

  const showAllFiles = () => {
    if (fileTreeTab() !== "changes") return
    setFileTreeTab("all")
  }

  const focusInput = () => {
    if (isChildSession()) return
    inputRef?.focus()
  }

  useSessionCommands({
    navigateMessageByOffset,
    setActiveMessage,
    focusInput,
    review: reviewTab,
  })

  const openReviewFile = createOpenReviewFile({
    showAllFiles,
    tabForPath: file.tab,
    openTab: tabs().open,
    setActive: tabs().setActive,
    loadFile: file.load,
  })

  const changesTitle = () => {
    if (!canReview()) {
      return null
    }

    const label = (option: ChangeMode) => {
      if (option === "git") return language.t("ui.sessionReview.title.git")
      if (option === "branch") return language.t("ui.sessionReview.title.branch")
      return language.t("ui.sessionReview.title.lastTurn")
    }

    return (
      <Select
        options={changesOptions()}
        current={store.changes}
        label={label}
        onSelect={(option) => option && setStore("changes", option)}
        
        
        valueClass="text-14-medium"
      />
    )
  }

  const empty = (text: string) => (
    <div class="h-full pb-32 flex flex-col items-center justify-center text-center gap-3 p-6">
      <div class="flex h-12 w-12 items-center justify-center rounded-lg bg-bg-surface border border-border-weaker-base text-text-secondary mb-1 transition-all">
        <Icon name="shield" class="w-6 h-6" />
      </div>
      <div class="text-sm font-medium text-text-primary max-w-64 leading-relaxed">{text}</div>
      <div class="text-xs text-text-tertiary font-mono">{language.t("session.empty.syncHint")}</div>
    </div>
  )

  const reviewEmptyText = createMemo(() => {
    if (store.changes === "git" || store.changes === "branch") {
      return language.t("session.review.noIterationChanges") ?? "Sin modificaciones de código en esta iteración"
    }
    return language.t("session.review.consoleReady") ?? "Consola lista. Los hallazgos y evidencias aparecerán aquí durante la ejecución."
  })

  const reviewEmpty = (input: { loadingClass: string }) => {
    if (store.changes === "git" || store.changes === "branch") {
      if (!reviewReady()) return <div class={input.loadingClass}>{language.t("session.review.loadingChanges")}</div>
      return empty(reviewEmptyText())
    }

    return empty(reviewEmptyText())
  }

  const reviewContent = (input: {
    diffStyle: DiffStyle
    onDiffStyleChange?: (style: DiffStyle) => void
    classes?: SessionReviewTabProps["classes"]
    loadingClass: string
  }) => (
    <Show when={!store.deferRender}>
      <SessionReviewTab
        title={changesTitle()}
        empty={reviewEmpty(input)}
        diffs={reviewDiffs}
        view={view}
        diffStyle={input.diffStyle}
        onDiffStyleChange={input.onDiffStyleChange}
        onScrollRef={(el) => setTree("reviewScroll", el)}
        focusedFile={tree.activeDiff}
        onLineComment={(comment) => addCommentToContext({ ...comment, origin: "review" })}
        onLineCommentUpdate={updateCommentInContext}
        onLineCommentDelete={removeCommentFromContext}
        lineCommentActions={reviewCommentActions()}
        commentMentions={{
          items: file.searchFilesAndDirectories,
        }}
        comments={comments.all()}
        focusedComment={comments.focus()}
        onFocusedCommentChange={comments.setFocus}
        onViewFile={openReviewFile}
        classes={input.classes}
      />
    </Show>
  )

  const reviewPanel = () => (
    <div class="flex flex-col h-full overflow-hidden bg-bg-elevated contain-strict">
      <div class="relative pt-2 flex-1 min-h-0 overflow-hidden">
        {reviewContent({
          diffStyle: layout.review.diffStyle(),
          onDiffStyleChange: layout.review.setDiffStyle,
          loadingClass: "px-6 py-4 text-text-weak",
        })}
      </div>
    </div>
  )

  createEffect(
    on(
      activeFileTab,
      (active) => {
        if (!active) return
        if (fileTreeTab() !== "changes") return
        showAllFiles()
      },
      { defer: true },
    ),
  )

  createEffect(() => {
    const id = params.id
    if (!id) return

    if (!wantsReview()) return
    if (sync.data.session_diff[id] !== undefined) return
    if (sync.status === "loading") return

    void sync.session.diff(id)
  })

  createEffect(
    on(
      () => [sessionKey(), wantsReview()] as const,
      ([key, wants]) => {
        if (diffFrame !== undefined) cancelAnimationFrame(diffFrame)
        if (diffTimer !== undefined) window.clearTimeout(diffTimer)
        diffFrame = undefined
        diffTimer = undefined
        if (!wants) return

        const id = params.id
        if (!id) return
        if (!untrack(() => sync.data.session_diff[id] !== undefined)) return

        diffFrame = requestAnimationFrame(() => {
          diffFrame = undefined
          diffTimer = window.setTimeout(() => {
            diffTimer = undefined
            if (sessionKey() !== key) return
            void sync.session.diff(id, { force: true })
          }, 0)
        })
      },
      { defer: true },
    ),
  )

  let treeDir: string | undefined
  createEffect(() => {
    const dir = sdk.directory
    if (!isDesktop()) return
    if (!layout.fileTree.opened()) return
    if (sync.status === "loading") return

    fileTreeTab()
    const refresh = treeDir !== dir
    treeDir = dir
    void (refresh ? file.tree.refresh("") : file.tree.list(""))
  })

  createEffect(
    on(
      () => sdk.directory,
      () => {
        const tab = activeFileTab()
        if (!tab) return
        const path = file.pathFromTab(tab)
        if (!path) return
        void file.load(path, { force: true })
      },
      { defer: true },
    ),
  )

  const autoScroll = createAutoScroll({
    working: () => true,
    overflowAnchor: "dynamic",
  })

  let scrollStateFrame: number | undefined
  let scrollStateTarget: HTMLDivElement | undefined
  let fillFrame: number | undefined

  const jumpThreshold = (el: HTMLDivElement) => Math.max(400, el.clientHeight)

  const updateScrollState = (el: HTMLDivElement) => {
    const max = el.scrollHeight - el.clientHeight
    const distance = max - el.scrollTop
    const overflow = max > 1
    const bottom = !overflow || distance <= 2
    const jump = overflow && distance > jumpThreshold(el)

    if (ui.scroll.overflow === overflow && ui.scroll.bottom === bottom && ui.scroll.jump === jump) return
    setUi("scroll", { overflow, bottom, jump })
  }

  const scheduleScrollState = (el: HTMLDivElement) => {
    scrollStateTarget = el
    if (scrollStateFrame !== undefined) return

    scrollStateFrame = requestAnimationFrame(() => {
      scrollStateFrame = undefined

      const target = scrollStateTarget
      scrollStateTarget = undefined
      if (!target) return

      updateScrollState(target)
    })
  }

  const resumeScroll = () => {
    setStore("messageId", undefined)
    autoScroll.forceScrollToBottom()
    clearMessageHash()

    const el = scroller
    if (el) scheduleScrollState(el)
  }

  // When the user returns to the bottom, treat the active message as "latest".
  createEffect(
    on(
      autoScroll.userScrolled,
      (scrolled) => {
        if (scrolled) return
        setStore("messageId", undefined)
        clearMessageHash()
      },
      { defer: true },
    ),
  )

  let fill = () => {}

  const setScrollRef = (el: HTMLDivElement | undefined) => {
    scroller = el
    autoScroll.scrollRef(el)
    if (!el) return
    scheduleScrollState(el)
    fill()
  }

  const markUserScroll = () => {
    scrollMark += 1
  }

  createResizeObserver(
    () => content,
    () => {
      const el = scroller
      if (el) scheduleScrollState(el)
      fill()
    },
  )

  const historyLoader = createSessionHistoryLoader({
    sessionID: () => params.id,
    loaded: () => messages().length,
    visibleUserMessages,
    historyMore,
    historyLoading,
    loadMore: (sessionID) => sync.session.history.loadMore(sessionID),
    userScrolled: autoScroll.userScrolled,
    scroller: () => scroller,
  })

  fill = () => {
    if (fillFrame !== undefined) return

    fillFrame = requestAnimationFrame(() => {
      fillFrame = undefined

      if (!params.id || !messagesReady()) return
      if (autoScroll.userScrolled() || historyLoading()) return

      const el = scroller
      if (!el) return
      if (el.scrollHeight > el.clientHeight + 1) return
      if (!historyMore()) return

      void historyLoader.loadAndReveal()
    })
  }

  createEffect(
    on(
      () =>
        [
          params.id,
          messagesReady(),
          historyMore(),
          historyLoading(),
          autoScroll.userScrolled(),
          visibleUserMessages().length,
        ] as const,
      ([id, ready, more, loading, scrolled]) => {
        if (!id || !ready || loading || scrolled) return
        if (!more) return
        fill()
      },
      { defer: true },
    ),
  )

  const draft = (id: string) =>
    extractPromptFromParts(sync.data.part[id] ?? [], {
      directory: sdk.directory,
      attachmentName: language.t("common.attachment"),
    })

  const line = (id: string) => {
    const text = draft(id)
      .map((part) => (part.type === "image" ? `[image:${part.filename}]` : part.content))
      .join("")
      .replace(/\s+/g, " ")
      .trim()
    if (text) return text
    return `[${language.t("common.attachment")}]`
  }

  const fail = (err: unknown) => {
    showToast({
      
      title: language.t("common.requestFailed"),
      description: formatServerError(err, language.t),
    })
  }

  const resumeInterruptedRun = async () => {
    const sessionID = params.id
    const run = interruptedRun()
    if (!sessionID || !run || ui.resumeRunning || ui.resumeAcknowledgedRunID !== run.id) return
    setUi("resumeRunning", true)
    const refreshTimer = setInterval(() => {
      void refreshExecutions()
    }, 1000)
    try {
      const response = await serverSDK.request(
        `/api/session/${encodeURIComponent(sessionID)}/resume`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ runID: run.id }),
        },
        sdk.directory,
      )
      if (!response.ok) {
        const details = await response.text().catch(() => "")
        throw new Error(details.trim() || `Failed to resume session: ${response.status}`)
      }
    } catch (error) {
      fail(error)
    } finally {
      clearInterval(refreshTimer)
      await refreshExecutions()
      setUi("resumeRunning", false)
    }
  }

  const merge = (next: NonNullable<ReturnType<typeof info>>) =>
    sync.set("session", (list) => {
      const idx = list.findIndex((item) => item.id === next.id)
      if (idx < 0) return list
      const out = list.slice()
      out[idx] = next
      return out
    })

  const roll = (sessionID: string, next: NonNullable<ReturnType<typeof info>>["revert"]) =>
    sync.set("session", (list) => {
      const idx = list.findIndex((item) => item.id === sessionID)
      if (idx < 0) return list
      const out = list.slice()
      out[idx] = { ...out[idx], revert: next }
      return out
    })

  const busy = (sessionID: string) => sync.data.session_working(sessionID)

  const queuedFollowups = createMemo(() => {
    const id = params.id
    if (!id) return emptyFollowups
    return followup.items[id] ?? emptyFollowups
  })

  const editingFollowup = createMemo(() => {
    const id = params.id
    if (!id) return
    return followup.edit[id]
  })

  const followupMutation = useMutation(() => ({
    mutationFn: async (input: { sessionID: string; id: string; manual?: boolean }) => {
      const item = (followup.items[input.sessionID] ?? []).find((entry) => entry.id === input.id)
      if (!item) return

      if (input.manual) setFollowup("paused", input.sessionID, undefined)
      setFollowup("failed", input.sessionID, undefined)

      const ok = await sendFollowupDraft({
        client: sdk.client,
        sync,
        serverSync,
        draft: item,
        optimisticBusy: item.sessionDirectory === sdk.directory,
      }).catch((err) => {
        setFollowup("failed", input.sessionID, input.id)
        fail(err)
        return false
      })
      if (!ok) return

      setFollowup("items", input.sessionID, (items) => (items ?? []).filter((entry) => entry.id !== input.id))
      if (input.manual) resumeScroll()
    },
  }))

  const followupBusy = (sessionID: string) =>
    followupMutation.isPending && followupMutation.variables?.sessionID === sessionID

  const sendingFollowup = createMemo(() => {
    const id = params.id
    if (!id) return
    if (!followupBusy(id)) return
    return followupMutation.variables?.id
  })

  const queueEnabled = createMemo(() => {
    const id = params.id
    if (!id) return false
    return settings.general.followup() === "queue" && busy(id) && !composer.blocked() && !isChildSession()
  })

  const followupText = (item: FollowupDraft) => {
    const text = item.prompt
      .map((part) => {
        if (part.type === "image") return `[image:${part.filename}]`
        if (part.type === "file") return `[file:${part.path}]`
        if (part.type === "agent") return `@${part.name}`
        return part.content
      })
      .join("")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => !!line)

    if (text) return text
    return `[${language.t("common.attachment")}]`
  }

  const queueFollowup = (draft: FollowupDraft) => {
    setFollowup("items", draft.sessionID, (items) => [
      ...(items ?? []),
      { id: Identifier.ascending("message"), ...draft },
    ])
    setFollowup("failed", draft.sessionID, undefined)
    setFollowup("paused", draft.sessionID, undefined)
  }

  const followupDock = createMemo(() => queuedFollowups().map((item) => ({ id: item.id, text: followupText(item) })))

  const sendFollowup = (sessionID: string, id: string, opts?: { manual?: boolean }) => {
    if (sync.session.get(sessionID)?.parentID) return Promise.resolve()
    const item = (followup.items[sessionID] ?? []).find((entry) => entry.id === id)
    if (!item) return Promise.resolve()
    if (followupBusy(sessionID)) return Promise.resolve()

    return followupMutation.mutateAsync({ sessionID, id, manual: opts?.manual })
  }

  const editFollowup = (id: string) => {
    const sessionID = params.id
    if (!sessionID) return
    if (followupBusy(sessionID)) return

    const item = queuedFollowups().find((entry) => entry.id === id)
    if (!item) return

    setFollowup("items", sessionID, (items) => (items ?? []).filter((entry) => entry.id !== id))
    setFollowup("failed", sessionID, (value) => (value === id ? undefined : value))
    setFollowup("edit", sessionID, {
      id: item.id,
      prompt: item.prompt,
      context: item.context,
    })
  }

  const clearFollowupEdit = () => {
    const id = params.id
    if (!id) return
    setFollowup("edit", id, undefined)
  }

  const halt = (sessionID: string) =>
    busy(sessionID) ? sdk.client.session.abort({ sessionID }).catch(() => {}) : Promise.resolve()

  const revertMutation = useMutation(() => ({
    mutationFn: async (input: { sessionID: string; messageID: string }) => {
      const prev = prompt.current().slice()
      const last = info()?.revert
      const value = draft(input.messageID)
      batch(() => {
        roll(input.sessionID, { messageID: input.messageID })
        prompt.set(value)
      })
      await halt(input.sessionID)
        .then(() => sdk.client.session.revert(input))
        .then((result) => {
          if (result.data) merge(result.data)
        })
        .catch((err) => {
          batch(() => {
            roll(input.sessionID, last)
            prompt.set(prev)
          })
          fail(err)
        })
    },
  }))

  const restoreMutation = useMutation(() => ({
    mutationFn: async (id: string) => {
      const sessionID = params.id
      if (!sessionID) return

      const next = userMessages().find((item) => item.id > id)
      const prev = prompt.current().slice()
      const last = info()?.revert

      batch(() => {
        roll(sessionID, next ? { messageID: next.id } : undefined)
        if (next) {
          prompt.set(draft(next.id))
          return
        }
        prompt.reset()
      })

      const task = !next
        ? halt(sessionID).then(() => sdk.client.session.unrevert({ sessionID }))
        : halt(sessionID).then(() =>
            sdk.client.session.revert({
              sessionID,
              messageID: next.id,
            }),
          )

      await task
        .then((result) => {
          if (result.data) merge(result.data)
        })
        .catch((err) => {
          batch(() => {
            roll(sessionID, last)
            prompt.set(prev)
          })
          fail(err)
        })
    },
  }))

  const reverting = createMemo(() => revertMutation.isPending || restoreMutation.isPending)
  const restoring = createMemo(() => (restoreMutation.isPending ? restoreMutation.variables : undefined))

  const revert = (input: { sessionID: string; messageID: string }) => {
    if (reverting()) return
    return revertMutation.mutateAsync(input)
  }

  const restore = (id: string) => {
    if (!params.id || reverting()) return
    return restoreMutation.mutateAsync(id)
  }

  const rolled = createMemo(() => {
    const id = revertMessageID()
    if (!id) return []
    return userMessages()
      .filter((item) => item.id >= id)
      .map((item) => ({ id: item.id, text: line(item.id) }))
  })

  const actions = { revert }

  createEffect(() => {
    const sessionID = params.id
    if (!sessionID) return

    const item = queuedFollowups()[0]
    if (!item) return
    if (followupBusy(sessionID)) return
    if (followup.failed[sessionID] === item.id) return
    if (followup.paused[sessionID]) return
    if (isChildSession()) return
    if (composer.blocked()) return
    if (busy(sessionID)) return

    void sendFollowup(sessionID, item.id)
  })

  createResizeObserver(
    () => promptDock,
    ({ height }) => {
      const next = Math.ceil(height)

      if (next === dockHeight) return

      const el = scroller
      const delta = next - dockHeight
      const stick = el
        ? !autoScroll.userScrolled() || el.scrollHeight - el.clientHeight - el.scrollTop < 10 + Math.max(0, delta)
        : false

      dockHeight = next

      if (stick) autoScroll.forceScrollToBottom()

      if (el) scheduleScrollState(el)
      fill()
    },
  )

  const { clearMessageHash, scrollToMessage } = useSessionHashScroll({
    sessionKey,
    sessionID: () => params.id,
    messagesReady,
    visibleUserMessages,
    historyMore,
    historyLoading,
    loadMore: (sessionID) => sync.session.history.loadMore(sessionID),
    currentMessageId: () => store.messageId,
    pendingMessage: () => ui.pendingMessage,
    setPendingMessage: (value) => setUi("pendingMessage", value),
    setActiveMessage,
    autoScroll,
    scroller: () => scroller,
    anchor,
    revealMessage: (id) => revealMessage(id),
    scheduleScrollState,
    consumePendingMessage: layout.pendingMessage.consume,
  })

  createEffect(
    on(
      () => params.id,
      (id) => {
        if (!id) requestAnimationFrame(() => inputRef?.focus())
      },
    ),
  )

  onMount(() => {
    makeEventListener(document, "keydown", handleKeyDown)
  })

  onCleanup(() => {
    if (reviewFrame !== undefined) cancelAnimationFrame(reviewFrame)
    if (diffFrame !== undefined) cancelAnimationFrame(diffFrame)
    if (diffTimer !== undefined) window.clearTimeout(diffTimer)
    if (scrollStateFrame !== undefined) cancelAnimationFrame(scrollStateFrame)
    if (fillFrame !== undefined) cancelAnimationFrame(fillFrame)
  })

  useUsageExceededDialogs()

  const composerRegion = (placement: "dock" | "inline") => (
    <SessionComposerRegion
      state={composer}
      ready={!store.deferRender && messagesReady()}
      centered={placement === "dock" && centered()}
      placement={placement}
      inputRef={(el) => {
        inputRef = el
      }}
      newSessionWorktree={newSessionWorktree()}
      onNewSessionWorktreeReset={() => setStore("newSessionWorktree", "main")}
      onSubmit={() => {
        comments.clear()
        resumeScroll()
      }}
      onResponseSubmit={resumeScroll}
      followup={
        params.id && !isChildSession()
          ? {
              queue: queueEnabled,
              items: followupDock(),
              sending: sendingFollowup(),
              edit: editingFollowup(),
              onQueue: queueFollowup,
              onAbort: () => {
                const id = params.id
                if (!id) return
                setFollowup("paused", id, true)
              },
              onSend: (id) => {
                void sendFollowup(params.id!, id, { manual: true })
              },
              onEdit: editFollowup,
              onEditLoaded: clearFollowupEdit,
            }
          : undefined
      }
      revert={
        rolled().length > 0
          ? {
              items: rolled(),
              restoring: restoring(),
              disabled: reverting(),
              onRestore: restore,
            }
          : undefined
      }
      setPromptDockRef={(el) => {
        promptDock = el
      }}
    />
  )

  return (
    <div class="relative size-full flex-1 min-h-0 overflow-hidden flex flex-col bg-bg-base">
      {sessionSync() ?? ""}
      <div
        classList={{
          "flex-1 min-h-0 flex flex-col bg-bg-base overflow-hidden": true,
          "p-2 gap-2": !!params.id && isDesktop(),
          "border-t border-border-weaker-base": !params.id || !isDesktop(),
        }}
      >
        <div
          ref={(el) => {
            sessionSplitContainer = el
            const width = Math.floor(el.clientWidth)
            if (width > 0 && width !== ui.sessionSplitWidth) setUi("sessionSplitWidth", width)
          }}
          class="relative flex-1 min-h-0 flex flex-col md:flex-row gap-2 min-w-0 overflow-hidden"
        >
          <Show when={!isDesktop() && !!params.id}>
            <Tabs value={store.mobileTab} class="h-auto">
              <Tabs.List>
                <Tabs.Trigger
                  value="session"
                  class="!w-1/2 !max-w-none"
                  classes={{ button: "w-full" }}
                  onClick={() => setStore("mobileTab", "session")}
                >
                  {language.t("session.tab.session")}
                </Tabs.Trigger>
                <Tabs.Trigger
                  value="changes"
                  class="!w-1/2 !max-w-none !border-r-0"
                  classes={{ button: "w-full" }}
                  onClick={() => setStore("mobileTab", "changes")}
                >
                  {hasReview()
                    ? language.t("session.review.filesChanged", { count: reviewCount() })
                    : language.t("session.review.change.other")}
                </Tabs.Trigger>
              </Tabs.List>
            </Tabs>
          </Show>

          <div
            id="main-content"
            classList={{
              "@container relative shrink-0 flex flex-col min-h-0 h-full flex-1 md:flex-none": true,
              "bg-bg-surface border border-border-weaker-base/80 rounded-[4px] shadow-xs overflow-hidden": !!params.id && isDesktop(),
              "bg-bg-base": !params.id || !isDesktop(),
              "duration-[240ms] ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none":
                !size.active() && !ui.reviewSnap,
              "transition-[width]": !isV2NewSessionPage(),
              "border-r border-border-weaker-base": !!params.id && !isDesktop(),
            }}
            style={{
              width: sessionPanelWidth(),
            }}
          >
            <Show when={params.id}>
              <SessionHeader />
            </Show>

            <Show when={executions()?.error}>
              {(error) => (
                <div
                  class="mx-3 mt-3 flex items-center justify-between gap-4 rounded border border-icon-warning-base/40 bg-bg-surface px-3 py-2"
                  role="alert"
                >
                  <div class="min-w-0">
                    <div class="text-13-medium text-text-strong">{language.t("session.run.loadError")}</div>
                    <div class="text-12-regular text-text-weak break-words">{error()}</div>
                  </div>
                  <button
                    type="button"
                    class="shrink-0 rounded border border-border-base px-3 py-1.5 text-12-medium text-text-strong hover:bg-bg-subtle"
                    onClick={() => void refreshExecutions()}
                  >
                    {language.t("errors.streaming.retry")}
                  </button>
                </div>
              )}
            </Show>

            <Show when={interruptedRun()}>
              <div
                class="mx-3 mt-3 flex items-center justify-between gap-4 rounded border border-icon-warning-base/40 bg-bg-surface px-3 py-2"
                role="status"
              >
                <div class="min-w-0">
                  <div class="text-13-medium text-text-strong">{language.t("session.run.interrupted.title")}</div>
                  <div class="text-12-regular text-text-weak">
                    {language.t("session.run.interrupted.description")}
                  </div>
                  <label class="mt-2 flex items-start gap-2 text-12-regular text-text-weak">
                    <input
                      class="mt-0.5"
                      type="checkbox"
                      checked={ui.resumeAcknowledgedRunID === interruptedRun()?.id}
                      onChange={(event) =>
                        setUi("resumeAcknowledgedRunID", event.currentTarget.checked ? interruptedRun()?.id : undefined)
                      }
                    />
                    <span>{language.t("session.run.interrupted.acknowledge")}</span>
                  </label>
                </div>
                <button
                  type="button"
                  class="shrink-0 rounded bg-accent px-3 py-1.5 text-12-medium text-accent-contrast hover:bg-accent/90 disabled:opacity-60"
                  disabled={ui.resumeRunning || ui.resumeAcknowledgedRunID !== interruptedRun()?.id}
                  onClick={() => void resumeInterruptedRun()}
                >
                  {ui.resumeRunning
                    ? language.t("session.run.interrupted.resuming")
                    : language.t("session.run.interrupted.resume")}
                </button>
              </div>
            </Show>

            <div
              class="flex-1 min-h-0 overflow-hidden flex flex-col"
            >
              <Switch>
                <Match when={params.id && mobileChanges()}>
                  <div class="relative h-full overflow-hidden">
                    {reviewContent({
                      diffStyle: "unified",
                      classes: {
                        root: "pb-8",
                        header: "px-4",
                        container: "px-4",
                      },
                      loadingClass: "px-4 py-4 text-text-weak",
                    })}
                  </div>
                </Match>
                <Match when={params.id}>
                  <Show
                    when={messagesReady()}
                    fallback={
                      <div class="size-full flex flex-col items-center justify-center gap-3 text-text-weak text-12-mono">
                        <Spinner class="size-5 text-accent" />
                        <span>{language.t("session.sync.inProgress")}</span>
                      </div>
                    }
                  >
                    <MessageTimeline
                      actions={actions}
                      scroll={ui.scroll}
                      onResumeScroll={resumeScroll}
                      setScrollRef={setScrollRef}
                      onScheduleScrollState={scheduleScrollState}
                      onAutoScrollHandleScroll={autoScroll.handleScroll}
                      onMarkScrollGesture={markScrollGesture}
                      hasScrollGesture={hasScrollGesture}
                      onUserScroll={markUserScroll}
                      onHistoryScroll={historyLoader.onScrollerScroll}
                      onAutoScrollInteraction={autoScroll.handleInteraction}
                      shouldAnchorBottom={() =>
                        !location.hash && !store.messageId && !ui.pendingMessage && !autoScroll.userScrolled()
                      }
                      centered={centered()}
                      setContentRef={(el) => {
                        content = el
                        autoScroll.contentRef(el)

                        const root = scroller
                        if (root) scheduleScrollState(root)
                      }}
                      historyShift={historyLoader.shift()}
                      userMessages={historyLoader.userMessages()}
                      anchor={anchor}
                      setRevealMessage={(fn) => {
                        revealMessage = fn
                      }}
                    />
                  </Show>
                </Match>
                <Match when={true}>
                  <NewSessionDesignView worktree={newSessionWorktree()}>{composerRegion("inline")}</NewSessionDesignView>
                </Match>
              </Switch>
            </div>

            <Show when={params.id}>{composerRegion("dock")}</Show>

            <Show when={desktopReviewOpen() && !compactSessionLayout()}>
              <div onPointerDown={() => size.start()}>
                <ResizeHandle
                  class="-right-1"
                  direction="horizontal"
                  size={sessionWidthClamped()}
                  min={sessionSplitSizing().minChatWidth}
                  max={sessionSplitSizing().maxChatWidth}
                  onResize={(width) => {
                    size.touch()
                    layout.session.resize(width)
                  }}
                  aria-label={language.t("session.panel.resize")}
                />
              </div>
            </Show>
          </div>

          <SessionSidePanel
            canReview={canReview}
            diffs={reviewDiffs}
            diffsReady={reviewReady}
            empty={reviewEmptyText}
            hasReview={hasReview}
            reviewCount={reviewCount}
            reviewPanel={reviewPanel}
            activeDiff={tree.activeDiff}
            focusReviewDiff={focusReviewDiff}
            compact={compactSessionLayout}
            reviewSnap={ui.reviewSnap}
            size={size}
          />
        </div>

        <TerminalPanel />
      </div>
    </div>
  )
}



