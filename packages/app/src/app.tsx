import "@/index.css"
import * as Sentry from "@sentry/solid"
import { I18nProvider } from "@argos/ui/context"
import { DialogProvider } from "@argos/ui/context/dialog"
import { FileComponentProvider } from "@argos/ui/context/file"
import { MarkedProvider } from "@argos/ui/context/marked"
import { File } from "@argos/ui/file"
import { ThinkingOrb } from "@argos/ui/thinking-orb"
import { ThemeProvider } from "@argos/ui/theme/context"
import { MetaProvider } from "@solidjs/meta"
import { type BaseRouterProps, Navigate, Route, Router } from "@solidjs/router"
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query"
import { Effect } from "effect"
import {
  type Component,
  createEffect,
  createMemo,
  createResource,
  ErrorBoundary,
  For,
  type JSX,
  lazy,
  onCleanup,
  type ParentProps,
  Show,
} from "solid-js"
import { createStore } from "solid-js/store"
import { Dynamic } from "solid-js/web"
import { CommandProvider } from "@/context/command"
import { CommentsProvider } from "@/context/comments"
import { FileProvider } from "@/context/file"
import { ServerSDKProvider } from "@/context/server-sdk"
import { ServerSyncProvider } from "@/context/server-sync"
import { GlobalProvider, useGlobal } from "@/context/global"
import { HighlightsProvider } from "@/context/highlights"
import { LanguageProvider, type Locale, useLanguage } from "@/context/language"
import { LayoutProvider } from "@/context/layout"
import { ModelsProvider } from "@/context/models"
import { NotificationProvider } from "@/context/notification"
import { PermissionProvider } from "@/context/permission"
import { PromptProvider } from "@/context/prompt"
import { ServerConnection, ServerProvider, serverName, useServer } from "@/context/server"
import { SettingsProvider } from "@/context/settings"
import { TerminalProvider } from "@/context/terminal"
import { TabsProvider } from "@/context/tabs"
import { WslServersProvider } from "@/wsl/context"
import DirectoryLayout from "@/pages/directory-layout"
import Layout from "@/pages/layout"
import { ErrorPage } from "./pages/error"
import { useCheckServerHealth } from "./utils/server-health"

const HomeRoute = lazy(() => import("@/pages/home"))
const DialogCommandPalette = lazy(() =>
  import("@/components/dialog-command-palette").then((module) => ({ default: module.DialogCommandPalette })),
)
const Session = lazy(() => import("@/pages/session"))
const FindingsPage = lazy(() => import("@/pages/findings"))
const ReportsPage = lazy(() => import("@/pages/reports"))
const TopologyPage = lazy(() => import("@/pages/topology"))
const CcmPage = lazy(() => import("@/pages/ccm"))
const GovernancePage = lazy(() => import("@/pages/governance"))
const StatusPage = lazy(() => import("@/pages/status"))

const AuditCcmRoute = Object.assign(() => <CcmPage />, { preload: () => {} })

const AuditGovernanceRoute = Object.assign(() => <GovernancePage />, { preload: () => {} })

const SessionRoute = Object.assign(
  () => (
    <SessionProviders>
      <Session />
    </SessionProviders>
  ),
  { preload: Session.preload },
)

function UiI18nBridge(props: ParentProps) {
  const language = useLanguage()
  return <I18nProvider value={{ locale: language.intl, t: language.t }}>{props.children}</I18nProvider>
}

declare global {
  interface Window {
    __ARGOS__?: {
      deepLinks?: string[]
    }
    api?: {
      setTitlebar?: (theme: { mode: "light" | "dark" }) => Promise<void>
      exportDebugLogs?: () => Promise<string>
      exportReportPdf?: (payload: { filename: string; contentBase64: string }) => Promise<{ path: string } | null>
      exportReportFile?: (payload: {
        filename: string
        contentBase64: string
        label?: string
        extensions?: string[]
      }) => Promise<{ path: string } | null>
      authProfiles?: {
        list: (
          sessionID: string,
        ) => Promise<{ id: string; name: string; username: string; hasBrowserSession: boolean }[]>
        save: (input: {
          sessionID: string
          name: string
          username: string
          password: string
          userSelector?: string
          passwordSelector?: string
          submitSelector?: string
          successSelector?: string
        }) => Promise<{ id: string; name: string; username: string; hasBrowserSession: boolean }>
        delete: (sessionID: string, id: string) => Promise<void>
      }
    }
  }
}

function QueryProvider(props: ParentProps) {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30 * 1000,
        refetchOnReconnect: false,
        refetchOnMount: false,
        refetchOnWindowFocus: false,
        retry: (failureCount, error: any) => {
          if (error?.status === 499 || (error?.status >= 400 && error?.status < 500)) return false
          return failureCount < 1
        },
      },
    },
  })
  return <QueryClientProvider client={client}>{props.children}</QueryClientProvider>
}

function BodyDesignClass() {
  createEffect(() => {
    if (typeof document === "undefined") return

    document.body.classList.add("font-(family-name:--font-family-text)", "text-sm", "font-normal")
  })

  return null
}

function CoreProviders(props: ParentProps<{ locale?: Locale }>) {
  return (
    <MetaProvider>
      <ThemeProvider
        onThemeApplied={(_, mode) => {
          void window.api?.setTitlebar?.({ mode })
        }}
      >
        <LanguageProvider locale={props.locale}>
          <UiI18nBridge>
            <ErrorBoundary
              fallback={(error) => {
                Sentry.captureException(error)
                return <ErrorPage error={error} />
              }}
            >
              {props.children}
            </ErrorBoundary>
          </UiI18nBridge>
        </LanguageProvider>
      </ThemeProvider>
    </MetaProvider>
  )
}

function DataProviders(props: ParentProps) {
  return (
    <QueryProvider>
      <WslServersProvider>
        <DialogProvider>
          <MarkedProvider>
            <FileComponentProvider component={File}>{props.children}</FileComponentProvider>
          </MarkedProvider>
        </DialogProvider>
      </WslServersProvider>
    </QueryProvider>
  )
}

function FeatureProviders(props: ParentProps) {
  return (
    <PermissionProvider>
      <LayoutProvider>
        <NotificationProvider>
          <ModelsProvider>
            <CommandProvider renderPalette={(input) => <DialogCommandPalette {...input} />}>
              <HighlightsProvider>{props.children}</HighlightsProvider>
            </CommandProvider>
          </ModelsProvider>
        </NotificationProvider>
      </LayoutProvider>
    </PermissionProvider>
  )
}

function SessionProviders(props: ParentProps) {
  return (
    <TerminalProvider>
      <FileProvider>
        <PromptProvider>
          <CommentsProvider>{props.children}</CommentsProvider>
        </PromptProvider>
      </FileProvider>
    </TerminalProvider>
  )
}

function RouterRoot(props: ParentProps<{ appChildren?: JSX.Element }>) {
  return (
    <AppShellProviders>
      {props.appChildren}
      {props.children}
    </AppShellProviders>
  )
}

function AppShellProviders(props: ParentProps) {
  return (
    <SettingsProvider>
      <BodyDesignClass />
      <FeatureProviders>
        <Layout>{props.children}</Layout>
      </FeatureProviders>
    </SettingsProvider>
  )
}

export function AppBaseProviders(props: ParentProps<{ locale?: Locale }>) {
  return (
    <CoreProviders locale={props.locale}>
      <DataProviders>{props.children}</DataProviders>
    </CoreProviders>
  )
}

function ServerContextProviders(props: ParentProps) {
  const global = useGlobal()
  return (
    <ServerSDKProvider createServerCtx={(conn) => global.createServerCtx(conn)}>
      <ServerSyncProvider createServerCtx={(conn) => global.createServerCtx(conn)}>{props.children}</ServerSyncProvider>
    </ServerSDKProvider>
  )
}

function ConnectionGate(props: ParentProps<{ disableHealthCheck?: boolean }>) {
  const server = useServer()
  const checkServerHealth = useCheckServerHealth()

  const [state, setState] = createStore<{ checkMode: "blocking" | "background" }>({
    checkMode: "blocking",
  })

  // performs repeated health check with a grace period for
  // non-http connections, otherwise fails instantly
  const [startupHealthCheck, healthCheckActions] = createResource(() =>
    props.disableHealthCheck
      ? true
      : Effect.gen(function* () {
          if (!server.current) return true
          const { http, type } = server.current

          while (true) {
            const res = yield* Effect.promise(() => checkServerHealth(http).catch(() => ({ healthy: false })))
            if (res.healthy) return true
            if (state.checkMode === "background" || type === "http") return false
          }
        }).pipe(
          Effect.timeoutOrElse({ duration: "10 seconds", orElse: () => Effect.succeed(false) }),
          Effect.ensuring(Effect.sync(() => setState("checkMode", "background"))),
          Effect.runPromise,
        ),
  )
  const checking = createMemo(
    () => state.checkMode === "blocking" && ["unresolved", "pending"].includes(startupHealthCheck.state),
  )

  return (
    <Show
      when={!checking()}
      fallback={
        <main class="h-dvh w-screen flex flex-col items-center justify-center bg-bg-base">
          <ThinkingOrb state="listening" size={64} />
        </main>
      }
    >
      <Show
        when={startupHealthCheck.latest}
        fallback={
          <ConnectionError
            onRetry={() => {
              if (state.checkMode === "background") void healthCheckActions.refetch()
            }}
            onServerSelected={(key) => {
              setState("checkMode", "blocking")
              server.setActive(key)
              void healthCheckActions.refetch()
            }}
          />
        }
      >
        {props.children}
      </Show>
    </Show>
  )
}

function ConnectionError(props: { onRetry?: () => void; onServerSelected?: (key: ServerConnection.Key) => void }) {
  const language = useLanguage()
  const server = useServer()
  const others = () => server.list.filter((s) => ServerConnection.key(s) !== server.key)
  const name = createMemo(() => server.name || server.key)
  const serverToken = "\u0000server\u0000"
  const unreachable = createMemo(() => language.t("app.server.unreachable", { server: serverToken }).split(serverToken))

  createEffect(() => {
    let timeoutId: ReturnType<typeof setTimeout>
    let delay = 1000
    let stopped = false

    const scheduleRetry = () => {
      timeoutId = setTimeout(() => {
        if (stopped) return
        props.onRetry?.()
        delay = Math.min(delay * 1.5, 15000)
        scheduleRetry()
      }, delay)
    }

    scheduleRetry()

    onCleanup(() => {
      stopped = true
      clearTimeout(timeoutId)
    })
  })

  return (
    <main class="h-dvh w-screen flex flex-col items-center justify-center bg-bg-base gap-6 p-6">
      <div class="flex flex-col items-center max-w-md text-center">
        <div class="mb-4">
          <ThinkingOrb state="listening" size={48} />
        </div>
        <p class="text-14-regular text-text-base">
          {unreachable()[0]}
          <span class="text-text-strong font-medium">{name()}</span>
          {unreachable()[1]}
        </p>
        <p class="mt-1 text-12-regular text-text-weak">{language.t("app.server.retrying")}</p>
      </div>
      <Show when={others().length > 0}>
        <div class="flex flex-col gap-2 w-full max-w-sm">
          <span class="text-12-regular text-text-base text-center">{language.t("app.server.otherServers")}</span>
          <div class="flex flex-col gap-1 bg-bg-surface rounded-lg p-2">
            <For each={others()}>
              {(conn) => {
                const key = ServerConnection.key(conn)
                return (
                  <button
                    type="button"
                    class="flex items-center gap-3 w-full px-3 py-2 rounded-md hover:bg-bg-elevated transition-colors text-left"
                    onClick={() => props.onServerSelected?.(key)}
                  >
                    <span class="text-14-regular text-text-strong truncate">{serverName(conn)}</span>
                  </button>
                )
              }}
            </For>
          </div>
        </div>
      </Show>
    </main>
  )
}

function ServerKey(props: ParentProps) {
  const server = useServer()
  return (
    <Show when={server.key} keyed>
      {props.children}
    </Show>
  )
}

export function AppInterface(props: {
  children?: JSX.Element
  defaultServer: ServerConnection.Key
  canonicalLocalServer?: ServerConnection.Key
  servers?: Array<ServerConnection.Any>
  router?: Component<BaseRouterProps>
  disableHealthCheck?: boolean
}) {
  return (
    <ServerProvider
      defaultServer={props.defaultServer}
      canonicalLocalServer={props.canonicalLocalServer}
      servers={props.servers}
    >
      <GlobalProvider>
        <ConnectionGate disableHealthCheck={props.disableHealthCheck}>
          <Dynamic
            component={props.router ?? Router}
            root={(routerProps) => (
              <TabsProvider>
                <ServerKey>
                  <ServerContextProviders>
                    <RouterRoot appChildren={props.children}>{routerProps.children}</RouterRoot>
                  </ServerContextProviders>
                </ServerKey>
              </TabsProvider>
            )}
          >
            <Route path="/auditorias" component={HomeRoute} />
            <Route path="/" component={HomeRoute} />
            <Route path="/auditorias/:dir" component={DirectoryLayout}>
              <Route path="/" component={() => <Navigate href="session" />} />
              <Route path="/session/:id?" component={SessionRoute} />
              <Route path="/findings" component={FindingsPage} />
              <Route path="/hallazgos" component={FindingsPage} />
              <Route path="/topology" component={TopologyPage} />
              <Route path="/topologia" component={TopologyPage} />
              <Route path="/reports" component={ReportsPage} />
              <Route path="/reporte" component={ReportsPage} />
              <Route path="/compliance" component={AuditCcmRoute} />
              <Route path="/cumplimiento" component={AuditCcmRoute} />
              <Route path="/governance" component={AuditGovernanceRoute} />
              <Route path="/gobernanza" component={AuditGovernanceRoute} />
              <Route path="/status" component={StatusPage} />
            </Route>
            <Route path="/:dir" component={DirectoryLayout}>
              <Route path="/" component={() => <Navigate href="session" />} />
              <Route path="/session/:id?" component={SessionRoute} />
              <Route path="/findings" component={FindingsPage} />
              <Route path="/hallazgos" component={FindingsPage} />
              <Route path="/topology" component={TopologyPage} />
              <Route path="/topologia" component={TopologyPage} />
              <Route path="/reports" component={ReportsPage} />
              <Route path="/reporte" component={ReportsPage} />
              <Route path="/compliance" component={AuditCcmRoute} />
              <Route path="/cumplimiento" component={AuditCcmRoute} />
              <Route path="/governance" component={AuditGovernanceRoute} />
              <Route path="/gobernanza" component={AuditGovernanceRoute} />
              <Route path="/status" component={StatusPage} />
            </Route>
          </Dynamic>
        </ConnectionGate>
      </GlobalProvider>
    </ServerProvider>
  )
}
