/**
 * traffic-panel.tsx
 *
 * Panel de tráfico HTTP de la sesión: el historial de exchanges que capturó
 * el escáner web, el detalle de cada request/response y el diff entre dos
 * de ellos.
 *
 * Es la pieza que le faltaba a Argos para el trabajo fino: hasta ahora una
 * tool encuentras algo y el auditor no podía re-ver la request exacta, ni
 * compararla con una segunda respuesta, ni reenviarla con una modificación.
 */

import { createEffect, createMemo, createResource, For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Button } from "@argos/ui/button"
import { Icon } from "@argos/ui/icon"
import { sendFollowupDraft } from "@/components/prompt-input/submit"
import { useLanguage } from "@/context/language"
import { useLocal } from "@/context/local"
import { useSDK } from "@/context/sdk"
import { useServerSync } from "@/context/server-sync"
import { useSync } from "@/context/sync"
import { showToast } from "@/utils/toast"
import { PanelBody, PanelErrorBoundary, PanelSection } from "./panel-ui"
import {
  loadTrafficDiff,
  loadTrafficHistory,
  type TrafficDiff,
  type TrafficExchange,
} from "./traffic-api"
import { buildReplayPrompt } from "./traffic-replay"

/** Cuántos exchanges trae el panel: el store puede tener miles. */
const HISTORY_LIMIT = 50

/** Los cuerpos se muestran truncados: el store tiene el cuerpo completo. */
const BODY_PREVIEW_CHARS = 4000

function statusTone(status: number) {
  if (status >= 500) return "text-severity-fg-critical"
  if (status >= 400) return "text-severity-fg-medium"
  if (status >= 300) return "text-severity-fg-info"
  if (status >= 200) return "text-severity-fg-low"
  return "text-text-tertiary"
}

function formatTime(timestamp: number) {
  if (!timestamp) return ""
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return ""
  return date.toISOString().replace("T", " ").slice(0, 19)
}

function truncate(value: string) {
  if (value.length <= BODY_PREVIEW_CHARS) return value
  return `${value.slice(0, BODY_PREVIEW_CHARS)}\n...`
}

function headerRows(headers: Record<string, string[]>) {
  return Object.entries(headers ?? {}).map(([name, values]) => ({
    name,
    value: (values ?? []).join(", "),
  }))
}

export function TrafficPanel(props: { sessionId: string }) {
  const language = useLanguage()
  const sdk = useSDK()
  const sync = useSync()
  const serverSync = useServerSync()
  const local = useLocal()

  const [state, setState] = createStore({
    /** Filtros que el usuario está escribiendo. */
    draft: { host: "", method: "", status: "", tool: "" },
    /** Filtros aplicados: son los que disparan la consulta. */
    applied: { host: "", method: "", status: "", tool: "" },
    selectedID: "",
    compareID: "",
    diff: undefined as TrafficDiff | undefined,
    diffError: "",
    sending: false,
  })

  const [history, { refetch }] = createResource(
    () =>
      JSON.stringify([
        props.sessionId,
        state.applied.host,
        state.applied.method,
        state.applied.status,
        state.applied.tool,
      ]),
    async () => {
      const result = await loadTrafficHistory(
        (...args) => sdk.request(...args),
        props.sessionId,
        state.applied,
        HISTORY_LIMIT,
      ).catch(() => undefined)
      return result ?? { exchanges: [] as TrafficExchange[], total: 0 }
    },
  )

  const exchanges = createMemo(() => history()?.exchanges ?? [])
  const total = createMemo(() => history()?.total ?? 0)

  const selected = createMemo(() => exchanges().find((item) => item.id === state.selectedID))

  // La primera request de la lista es la que el auditor quiere ver: se
  // selecciona sola para que el panel no arranque vacío.
  createEffect(() => {
    const list = exchanges()
    if (list.length === 0) return
    if (!list.some((item) => item.id === state.selectedID)) {
      setState("selectedID", list[0].id)
    }
  })

  // Los filtros se aplican con un debounce: escribir en el campo no puede
  // disparar una request por tecla.
  createEffect(() => {
    const draft = { ...state.draft }
    const timer = setTimeout(() => {
      setState("applied", {
        host: draft.host.trim(),
        method: draft.method.trim(),
        status: draft.status.trim(),
        tool: draft.tool.trim(),
      })
    }, 350)
    return () => clearTimeout(timer)
  })

  const loadDiff = async (aID: string, bID: string) => {
    if (!aID || !bID || aID === bID) {
      setState({ diff: undefined, diffError: "" })
      return
    }
    try {
      const diff = await loadTrafficDiff((...args) => sdk.request(...args), props.sessionId, aID, bID)
      setState({ diff, diffError: diff ? "" : language.t("traffic.diff.unavailable") })
    } catch {
      setState({ diff: undefined, diffError: language.t("traffic.diff.error") })
    }
  }

  createEffect(() => {
    const aID = state.selectedID
    const bID = state.compareID
    void loadDiff(aID, bID)
  })

  /**
   * El replay lo ejecuta el agente, no la UI: la request tiene que salir
   * del cliente atado al ScopeGuard del binario Go (IP-pinning, rate limit y
   * audit log encadenado) y el override de scope se verifica ahí.
   */
  const requestReplay = async (exchange: TrafficExchange) => {
    const model = local.model.current()
    const agent = local.agent.current()
    if (!model || !agent) {
      showToast({ title: language.t("traffic.replay.failed") })
      return
    }
    setState("sending", true)
    const text = buildReplayPrompt(exchange, language.t)
    try {
      await sendFollowupDraft({
        client: sdk.client,
        sync,
        serverSync,
        draft: {
          sessionID: props.sessionId,
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
        title: language.t("traffic.replay.sent"),
        description: exchange.method + " " + exchange.url,
      })
    } catch {
      showToast({ title: language.t("traffic.replay.failed") })
    } finally {
      setState("sending", false)
    }
  }

  return (
    <PanelErrorBoundary name={language.t("session.panel.traffic")}>
      <div class="flex h-full min-h-0 flex-col overflow-hidden">
        <div class="flex shrink-0 flex-col gap-2 border-b border-border-weaker-base/70 bg-bg-surface px-3 py-2">
          <div class="flex flex-wrap items-center gap-2">
            <div class="flex items-center gap-1.5">
              <Icon name="globe" class="text-text-tertiary" size="small" />
              <span class="font-mono text-10-medium uppercase tracking-wider text-text-weak">
                {language.t("traffic.list.title")}
              </span>
            </div>
            <span class="font-mono text-10-regular text-text-tertiary tabular-nums">
              {language.t("traffic.list.count", { count: exchanges().length, total: total() })}
            </span>
            <div class="grow" />
            <Button
              variant="ghost"
              size="small"
              icon="refresh"
              title={language.t("traffic.refresh")}
              onClick={() => void refetch()}
            />
          </div>
          <div class="flex flex-wrap items-center gap-1.5">
            <input
              type="text"
              value={state.draft.host}
              onInput={(event) => setState("draft", "host", event.currentTarget.value)}
              placeholder={language.t("traffic.filters.host")}
              class="min-w-0 flex-1 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 font-mono text-10-regular text-text-primary placeholder:text-text-tertiary"
            />
            <input
              type="text"
              value={state.draft.method}
              onInput={(event) => setState("draft", "method", event.currentTarget.value)}
              placeholder={language.t("traffic.filters.method")}
              class="w-20 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 font-mono text-10-regular text-text-primary placeholder:text-text-tertiary"
            />
            <input
              type="text"
              value={state.draft.status}
              onInput={(event) => setState("draft", "status", event.currentTarget.value)}
              placeholder={language.t("traffic.filters.status")}
              class="w-20 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 font-mono text-10-regular text-text-primary placeholder:text-text-tertiary"
            />
            <input
              type="text"
              value={state.draft.tool}
              onInput={(event) => setState("draft", "tool", event.currentTarget.value)}
              placeholder={language.t("traffic.filters.tool")}
              class="w-28 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 font-mono text-10-regular text-text-primary placeholder:text-text-tertiary"
            />
          </div>
        </div>

        <Show
          when={exchanges().length > 0}
          fallback={
            <div class="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center">
              <Icon name="code-lines" class="size-8 text-text-tertiary opacity-40" />
              <div class="text-12-medium text-text-primary">{language.t("traffic.empty.title")}</div>
              <div class="max-w-80 text-11-regular text-text-secondary">{language.t("traffic.empty.sub")}</div>
            </div>
          }
        >
          <div class="flex min-h-0 flex-1">
            {/* Lista de exchanges */}
            <div class="flex w-[42%] min-w-0 flex-col overflow-y-auto border-r border-border-weaker-base/60">
              <For each={exchanges()}>
                {(exchange) => (
                  <button
                    type="button"
                    onClick={() => setState("selectedID", exchange.id)}
                    class={`flex w-full flex-col gap-1 border-b border-border-weaker-base/40 px-3 py-2 text-left transition-colors cursor-pointer ${
                      exchange.id === state.selectedID
                        ? "bg-bg-elevated"
                        : "hover:bg-bg-surface"
                    }`}
                  >
                    <div class="flex items-center gap-2">
                      <span class="font-mono text-10-bold uppercase tracking-wider text-text-secondary">
                        {exchange.method}
                      </span>
                      <span class={`font-mono text-10-bold tabular-nums ${statusTone(exchange.status)}`}>
                        {exchange.status}
                      </span>
                      <span class="grow" />
                      <span class="font-mono text-9-regular text-text-tertiary tabular-nums">
                        {exchange.durationMs}ms
                      </span>
                    </div>
                    <div class="truncate font-mono text-10-regular text-text-primary">{exchange.url}</div>
                    <div class="flex items-center gap-2 font-mono text-9-regular text-text-tertiary">
                      <span>{formatTime(exchange.timestamp)}</span>
                      <Show when={exchange.sourceTool}>
                        <span>·</span>
                        <span>{exchange.sourceTool}</span>
                      </Show>
                      <Show when={!exchange.scopeAllowed}>
                        <span>·</span>
                        <span class="text-severity-fg-medium">{language.t("traffic.list.outOfScope")}</span>
                      </Show>
                    </div>
                  </button>
                )}
              </For>
            </div>

            {/* Detalle + diff */}
            <div class="flex min-w-0 flex-1 flex-col overflow-y-auto">
              <PanelBody class="gap-4">
                <Show when={selected()}>
                  {(exchange) => (
                    <>
                      <PanelSection
                        label={language.t("traffic.detail.request")}
                        actions={
                          <Button
                            variant="ghost"
                            size="small"
                            icon="refresh"
                            disabled={state.sending}
                            title={language.t("traffic.replay.button")}
                            onClick={() => void requestReplay(exchange())}
                          >
                            <span class="font-mono text-10-medium uppercase tracking-wider">
                              {language.t("traffic.replay.button")}
                            </span>
                          </Button>
                        }
                      >
                        <div class="flex flex-col gap-1.5">
                          <div class="font-mono text-11-medium text-text-primary break-all">
                            {exchange().method} {exchange().url}
                          </div>
                          <div class="flex flex-wrap items-center gap-2 font-mono text-10-regular text-text-tertiary">
                            <span>{language.t("traffic.detail.id")}: {exchange().id}</span>
                            <Show when={exchange().sourceTool}>
                              <span>·</span>
                              <span>{exchange().sourceTool}</span>
                            </Show>
                            <span>·</span>
                            <span>{formatTime(exchange().timestamp)}</span>
                          </div>
                        </div>
                      </PanelSection>

                      <PanelSection label={language.t("traffic.detail.requestHeaders")}>
                        <For each={headerRows(exchange().requestHeaders)}>
                          {(row) => (
                            <div class="flex gap-2 font-mono text-10-regular">
                              <span class="shrink-0 text-text-weak">{row.name}</span>
                              <span class="min-w-0 break-all text-text-secondary">{row.value}</span>
                            </div>
                          )}
                        </For>
                      </PanelSection>

                      <Show when={exchange().requestBody}>
                        <PanelSection label={language.t("traffic.detail.requestBody")}>
                          <pre class="max-h-48 overflow-auto rounded-sm border border-border-weaker-base/60 bg-bg-base p-2 font-mono text-10-regular whitespace-pre-wrap break-all text-text-secondary">
                            {truncate(exchange().requestBody)}
                          </pre>
                        </PanelSection>
                      </Show>

                      <PanelSection label={language.t("traffic.detail.response")}>
                        <div class="flex items-center gap-2 font-mono text-11-medium">
                          <span class={statusTone(exchange().status)}>{exchange().status}</span>
                          <span class="text-text-tertiary">{exchange().durationMs}ms</span>
                          <span class="text-text-tertiary">
                            {exchange().responseBodySize} {language.t("traffic.detail.bytes")}
                          </span>
                        </div>
                        <For each={headerRows(exchange().responseHeaders)}>
                          {(row) => (
                            <div class="flex gap-2 font-mono text-10-regular">
                              <span class="shrink-0 text-text-weak">{row.name}</span>
                              <span class="min-w-0 break-all text-text-secondary">{row.value}</span>
                            </div>
                          )}
                        </For>
                      </PanelSection>

                      <Show when={exchange().responseBody}>
                        <PanelSection label={language.t("traffic.detail.responseBody")}>
                          <pre class="max-h-48 overflow-auto rounded-sm border border-border-weaker-base/60 bg-bg-base p-2 font-mono text-10-regular whitespace-pre-wrap break-all text-text-secondary">
                            {truncate(exchange().responseBody)}
                          </pre>
                        </PanelSection>
                      </Show>
                    </>
                  )}
                </Show>

                <PanelSection label={language.t("traffic.diff.title")}>
                  <select
                    value={state.compareID}
                    onChange={(event) => setState("compareID", event.currentTarget.value)}
                    class="w-full rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 font-mono text-10-regular text-text-primary"
                  >
                    <option value="">{language.t("traffic.diff.compare")}</option>
                    <For each={exchanges()}>
                      {(exchange) => (
                        <option value={exchange.id}>
                          {exchange.method} {exchange.status} {exchange.url}
                        </option>
                      )}
                    </For>
                  </select>

                  <Show when={state.diffError}>
                    <div class="font-mono text-10-regular text-severity-fg-medium">{state.diffError}</div>
                  </Show>

                  <Show when={state.diff}>
                    {(diff) => (
                      <div class="flex flex-col gap-2">
                        <div class="flex flex-wrap items-center gap-2 font-mono text-10-regular">
                          <span
                            class={
                              diff().identical
                                ? "text-severity-fg-low"
                                : "text-severity-fg-medium"
                            }
                          >
                            {diff().identical
                              ? language.t("traffic.diff.identical")
                              : language.t("traffic.diff.changed")}
                          </span>
                          <Show when={diff().statusChanged}>
                            <span class="text-text-secondary">
                              {language.t("traffic.diff.status")}: {diff().statusA} → {diff().statusB}
                            </span>
                          </Show>
                          <Show when={diff().bodyChanged}>
                            <span class="text-text-secondary">
                              {language.t("traffic.diff.body")}: +{diff().bodyLinesAdded} / -
                              {diff().bodyLinesRemoved}
                            </span>
                          </Show>
                        </div>

                        <For each={[...diff().headersAdded, ...diff().headersRemoved, ...diff().headersChanged]}>
                          {(change) => (
                            <div class="font-mono text-10-regular">
                              <span class="text-text-weak">{change.name}</span>
                              <Show when={change.a}>
                                <span class="text-severity-fg-medium"> {change.a}</span>
                              </Show>
                              <Show when={change.b}>
                                <span class="text-text-tertiary"> → {change.b}</span>
                              </Show>
                            </div>
                          )}
                        </For>

                        <Show when={diff().bodyDiff}>
                          <pre class="max-h-64 overflow-auto rounded-sm border border-border-weaker-base/60 bg-bg-base p-2 font-mono text-10-regular whitespace-pre-wrap text-text-secondary">
                            {diff().bodyDiff}
                          </pre>
                        </Show>
                      </div>
                    )}
                  </Show>
                </PanelSection>
              </PanelBody>
            </div>
          </div>
        </Show>
      </div>
    </PanelErrorBoundary>
  )
}
