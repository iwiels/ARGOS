import { TextField } from "@argos/ui/text-field"
import * as Sentry from "@sentry/solid"
import { Logo } from "@argos/ui/logo"
import { Button } from "@argos/ui/button"
import { Component, createSignal, onMount, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { usePlatform } from "@/context/platform"
import { useLanguage } from "@/context/language"
import { errorDescriptionKey } from "./error-description"

export type InitError = {
  name: string
  data: Record<string, unknown>
}

type Translator = ReturnType<typeof useLanguage>["t"]
const CHAIN_SEPARATOR = "\n" + "─".repeat(40) + "\n"

function isIssue(value: unknown): value is { message: string; path: string[] } {
  if (!value || typeof value !== "object") return false
  if (!("message" in value) || !("path" in value)) return false
  const message = (value as { message: unknown }).message
  const path = (value as { path: unknown }).path
  if (typeof message !== "string") return false
  if (!Array.isArray(path)) return false
  return path.every((part) => typeof part === "string")
}

function isInitError(error: unknown): error is InitError {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    "data" in error &&
    typeof (error as InitError).data === "object"
  )
}

function safeJson(value: unknown, circular: string): string {
  const seen = new WeakSet<object>()
  const json = JSON.stringify(
    value,
    (_key, val) => {
      if (typeof val === "bigint") return val.toString()
      if (typeof val === "object" && val) {
        if (seen.has(val)) return circular
        seen.add(val)
      }
      return val
    },
    2,
  )
  return json ?? String(value)
}

function formatInitError(error: InitError, t: Translator): string {
  const data = error.data
  const json = (value: unknown) => safeJson(value, t("error.page.circular"))
  switch (error.name) {
    case "MCPFailed": {
      const name = typeof data.name === "string" ? data.name : ""
      return t("error.chain.mcpFailed", { name })
    }
    case "ProviderAuthError": {
      const providerID = typeof data.providerID === "string" ? data.providerID : t("common.unknown")
      const message = typeof data.message === "string" ? data.message : json(data.message)
      return t("error.chain.providerAuthFailed", { provider: providerID, message })
    }
    case "APIError": {
      const message = typeof data.message === "string" ? data.message : t("error.chain.apiError")
      const lines: string[] = [message]

      if (typeof data.statusCode === "number") {
        lines.push(t("error.chain.status", { status: data.statusCode }))
      }

      if (typeof data.isRetryable === "boolean") {
        lines.push(t("error.chain.retryable", { retryable: data.isRetryable }))
      }

      if (typeof data.responseBody === "string" && data.responseBody) {
        lines.push(t("error.chain.responseBody", { body: data.responseBody }))
      }

      return lines.join("\n")
    }
    case "ProviderModelNotFoundError": {
      const { providerID, modelID, suggestions } = data as {
        providerID: string
        modelID: string
        suggestions?: string[]
      }

      const suggestionsLine =
        Array.isArray(suggestions) && suggestions.length
          ? [t("error.chain.didYouMean", { suggestions: suggestions.join(", ") })]
          : []

      return [
        t("error.chain.modelNotFound", { provider: providerID, model: modelID }),
        ...suggestionsLine,
        t("error.chain.checkConfig"),
      ].join("\n")
    }
    case "ProviderInitError": {
      const providerID = typeof data.providerID === "string" ? data.providerID : t("common.unknown")
      return t("error.chain.providerInitFailed", { provider: providerID })
    }
    case "ConfigJsonError": {
      const path = typeof data.path === "string" ? data.path : json(data.path)
      const message = typeof data.message === "string" ? data.message : ""
      if (message) return t("error.chain.configJsonInvalidWithMessage", { path, message })
      return t("error.chain.configJsonInvalid", { path })
    }
    case "ConfigDirectoryTypoError": {
      const path = typeof data.path === "string" ? data.path : json(data.path)
      const dir = typeof data.dir === "string" ? data.dir : json(data.dir)
      const suggestion = typeof data.suggestion === "string" ? data.suggestion : json(data.suggestion)
      return t("error.chain.configDirectoryTypo", { dir, path, suggestion })
    }
    case "ConfigFrontmatterError": {
      const path = typeof data.path === "string" ? data.path : json(data.path)
      const message = typeof data.message === "string" ? data.message : json(data.message)
      return t("error.chain.configFrontmatterError", { path, message })
    }
    case "ConfigInvalidError": {
      const issues = Array.isArray(data.issues)
        ? data.issues.filter(isIssue).map((issue) => "↳ " + issue.message + " " + issue.path.join("."))
        : []
      const message = typeof data.message === "string" ? data.message : ""
      const path = typeof data.path === "string" ? data.path : json(data.path)

      const line = message
        ? t("error.chain.configInvalidWithMessage", { path, message })
        : t("error.chain.configInvalid", { path })

      return [line, ...issues].join("\n")
    }
    case "UnknownError":
      return typeof data.message === "string" ? data.message : json(data)
    default:
      if (typeof data.message === "string") return data.message
      return json(data)
  }
}

function formatErrorChain(error: unknown, t: Translator, depth = 0, parentMessage?: string): string {
  const json = (value: unknown) => safeJson(value, t("error.page.circular"))
  if (!error) return t("error.chain.unknown")

  if (isInitError(error)) {
    const message = formatInitError(error, t)
    if (depth > 0 && parentMessage === message) return ""
    const indent = depth > 0 ? `\n${CHAIN_SEPARATOR}${t("error.chain.causedBy")}\n` : ""
    return indent + `${error.name}\n${message}`
  }

  if (error instanceof Error) {
    const isDuplicate = depth > 0 && parentMessage === error.message
    const parts: string[] = []
    const indent = depth > 0 ? `\n${CHAIN_SEPARATOR}${t("error.chain.causedBy")}\n` : ""

    const header = `${error.name}${error.message ? `: ${error.message}` : ""}`
    const stack = error.stack?.trim()

    if (stack) {
      const startsWithHeader = stack.startsWith(header)

      if (isDuplicate && startsWithHeader) {
        const trace = stack.split("\n").slice(1).join("\n").trim()
        if (trace) {
          parts.push(indent + trace)
        }
      }

      if (isDuplicate && !startsWithHeader) {
        parts.push(indent + stack)
      }

      if (!isDuplicate && startsWithHeader) {
        parts.push(indent + stack)
      }

      if (!isDuplicate && !startsWithHeader) {
        parts.push(indent + `${header}\n${stack}`)
      }
    }

    if (!stack && !isDuplicate) {
      parts.push(indent + header)
    }

    if (error.cause) {
      const causeResult = formatErrorChain(error.cause, t, depth + 1, error.message)
      if (causeResult) {
        parts.push(causeResult)
      }
    }

    return parts.join("\n\n")
  }

  if (typeof error === "string") {
    if (depth > 0 && parentMessage === error) return ""
    const indent = depth > 0 ? `\n${CHAIN_SEPARATOR}${t("error.chain.causedBy")}\n` : ""
    return indent + error
  }

  const indent = depth > 0 ? `\n${CHAIN_SEPARATOR}${t("error.chain.causedBy")}\n` : ""
  return indent + json(error)
}

function formatError(error: unknown, t: Translator): string {
  return formatErrorChain(error, t, 0)
}

function isLocalStartupFailure(error: unknown) {
  return typeof error === "object" && error !== null && "localServerStartup" in error
}

interface ErrorPageProps {
  error: unknown
}

export const ErrorPage: Component<ErrorPageProps> = (props) => {
  const platform = usePlatform()
  const language = useLanguage()
  const formattedError = () => formatError(props.error, language.t)
  let recordedFatalError: Promise<void> | undefined
  const [store, setStore] = createStore({
    actionError: undefined as string | undefined,
    wslBusy: false,
    wslPendingRestart: false,
    wslMessage: "",
  })

  const wslSetup = () =>
    platform.platform === "desktop" && platform.os === "windows" ? platform.wslSetup : undefined
  const localStartupFailure = () => isLocalStartupFailure(props.error)
  const showWslSetup = () => localStartupFailure() && !!wslSetup()
  const errorText = () => (props.error instanceof Error ? props.error.message : String(props.error))
  const showInstallWsl = () =>
    showWslSetup() && /requires WSL 2|wsl --install|WSL is not installed|WSL 2 on Windows/i.test(errorText())

  async function installWsl() {
    const api = wslSetup()
    if (!api) return
    setStore("wslBusy", true)
    setStore("actionError", undefined)
    setStore("wslMessage", "")
    try {
      await api.installWsl()
      const state = await api.getState()
      setStore("wslPendingRestart", state.pendingRestart)
      setStore(
        "wslMessage",
        state.pendingRestart
          ? language.t("wsl.onboarding.windowsRestartRequired")
          : language.t("wsl.onboarding.ready"),
      )
    } catch (error) {
      setStore("actionError", formatError(error, language.t))
    } finally {
      setStore("wslBusy", false)
    }
  }

  function ensureFatalErrorRecorded() {
    recordedFatalError ??=
      platform.recordFatalRendererError?.({
        error: formattedError(),
        url: location.href,
        version: platform.version,
        platform: platform.platform,
        os: platform.os,
      }) ?? Promise.resolve()
    return recordedFatalError
  }

  onMount(() => {
    void ensureFatalErrorRecorded().catch(() => undefined)
    const api = wslSetup()
    if (!api) return
    void api
      .getState()
      .then((state) => setStore("wslPendingRestart", state.pendingRestart))
      .catch(() => undefined)
  })

  async function checkForUpdates() {
    const state = await platform.updater?.check()
    setStore("actionError", state?.status === "error" ? state.message : undefined)
  }

  async function installUpdate() {
    await platform.updater
      ?.install()
      .then(() => setStore("actionError", undefined))
      .catch((err) => {
        setStore("actionError", formatError(err, language.t))
      })
  }

  const updateVersion = () => {
    const state = platform.updater?.state()
    if (state?.status !== "ready") return
    return state.version
  }

  async function exportDebugLogs() {
    const exportLogs = platform.exportDebugLogs
    if (!exportLogs) return
    await ensureFatalErrorRecorded()
      .then(() => exportLogs())
      .then(() => setStore("actionError", undefined))
      .catch((err) => {
        setStore("actionError", formatError(err, language.t))
      })
  }

  return (
    <div class="relative flex-1 min-h-dvh size-full min-h-0 flex flex-col items-center justify-center bg-bg-base">
      <div class="w-2/3 max-w-3xl flex flex-col items-center justify-center gap-8">
        <Logo class="w-58.5 opacity-12 shrink-0" />
        <div class="flex flex-col items-center gap-2 text-center">
          <h1 class="text-lg font-medium text-text-strong">{language.t("error.page.title")}</h1>
          <p class="text-sm text-text-weak">{language.t(errorDescriptionKey(props.error))}</p>
        </div>
        <Show when={showWslSetup()}>
          <div class="w-full rounded-lg border border-border-weak-base bg-bg-surface p-4 flex flex-col gap-3 text-left">
            <div class="text-sm font-medium text-text-strong">{language.t("wsl.onboarding.wsl2Required")}</div>
            <p class="text-sm text-text-weak">{language.t("wsl.onboarding.required")}</p>
            <div class="flex flex-row flex-wrap items-center gap-3">
              <Show when={showInstallWsl()}>
                <Button size="large" onClick={installWsl} disabled={store.wslBusy}>
                  {store.wslBusy
                    ? language.t("wsl.onboarding.checkingRuntime")
                    : language.t("wsl.onboarding.installWsl")}
                </Button>
              </Show>
              <Button size="large" variant="ghost" onClick={() => void platform.restart()}>
                {language.t("error.page.action.restart")}
              </Button>
            </div>
            <Show when={store.wslPendingRestart}>
              <p class="text-xs text-icon-warning-base">{language.t("wsl.onboarding.windowsRestartRequired")}</p>
            </Show>
            <Show when={store.wslMessage}>
              <p class="text-xs text-text-weak">{store.wslMessage}</p>
            </Show>
          </div>
        </Show>
        <TextField
          value={formattedError()}
          readOnly
          copyable
          multiline
          class="max-h-96 w-full font-mono text-xs no-scrollbar"
          label={language.t("error.page.details.label")}
          hideLabel
        />
        <div class="flex flex-row items-center justify-center gap-3 flex-wrap max-w-64">
          <Button size="large" onClick={platform.restart}>
            {language.t("error.page.action.restart")}
          </Button>
          <Show when={platform.platform === "desktop" && platform.exportDebugLogs}>
            <Button size="large" variant="ghost" onClick={exportDebugLogs}>
              {language.t("error.page.action.exportLogs")}
            </Button>
          </Show>
          <Show when={Sentry.isEnabled}>
            {(_) => {
              const [reported, setReported] = createSignal(false)
              return (
                <Button
                  size="large"
                  disabled={reported()}
                  onClick={() => {
                    Sentry.captureException(props.error)
                    setReported(true)
                  }}
                >
                  {language.t(reported() ? "error.page.action.reported" : "error.page.action.report")}
                </Button>
              )
            }}
          </Show>
          <Show when={platform.updater}>
            <Show
              when={updateVersion()}
              fallback={
                <Button
                  size="large"
                  variant="ghost"
                  onClick={checkForUpdates}
                  disabled={["checking", "downloading", "installing"].includes(platform.updater?.state().status ?? "")}
                >
                  {platform.updater?.state().status === "checking"
                    ? language.t("error.page.action.checking")
                    : language.t("error.page.action.checkUpdates")}
                </Button>
              }
            >
              {(version) => (
                <Button size="large" onClick={installUpdate}>
                  {language.t("error.page.action.updateTo", { version: version() })}
                </Button>
              )}
            </Show>
          </Show>
        </div>
        <Show when={store.actionError}>
          {(message) => <p class="text-xs text-danger text-center max-w-2xl">{message()}</p>}
        </Show>
        <div class="flex flex-col items-center gap-2">
          <div class="flex items-center justify-center gap-1">{language.t("error.page.report.prefix")}</div>
          <Show when={platform.version}>
            {(version) => (
              <p class="text-xs text-text-weak">{language.t("error.page.version", { version: version() })}</p>
            )}
          </Show>
        </div>
      </div>
    </div>
  )
}


