import { For, Show, createEffect, createSignal, onCleanup, untrack } from "solid-js"
import { Button } from "@argos/ui/button"
import { useLanguage } from "@/context/language"
import { useSDK } from "@/context/sdk"
import { showToast } from "@/utils/toast"
import { findingStatusLabelKey, type Finding } from "./findings-data"
import {
  type FindingCase,
  type FindingCaseOperation,
  type FindingCaseStatus,
  type FindingCaseTransition,
  loadFindingCaseHistory,
  loadFindingCaseOperations,
  loadSessionFindingCases,
  loadSessionFindings,
  mergeFindingCases,
  reverseFindingCaseOperation,
  splitFindingCase,
  updateFindingCaseStatus,
} from "./security-findings-api"

const CASE_STATUSES: FindingCaseStatus[] = ["open", "in-progress", "remediated", "accepted-risk"]

const dateInputValue = (timestamp: number) => {
  const date = new Date(timestamp)
  const pad = (value: number) => String(value).padStart(2, "0")
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

function statusLabel(language: ReturnType<typeof useLanguage>, status: FindingCaseStatus) {
  return language.t(findingStatusLabelKey(status) ?? status)
}

function FindingCaseRow(props: {
  record: FindingCase
  records: FindingCase[]
  findings: Finding[]
  sessionID: string
  onSaved: (record: FindingCase) => void
  onChanged: () => void
  refreshVersion: number
}) {
  const language = useLanguage()
  const sdk = useSDK()
  const [status, setStatus] = createSignal<FindingCaseStatus>(props.record.status)
  const [reason, setReason] = createSignal(props.record.statusReason ?? "")
  const [expiry, setExpiry] = createSignal(
    props.record.acceptedRiskUntil ? dateInputValue(props.record.acceptedRiskUntil) : "",
  )
  const [saving, setSaving] = createSignal(false)
  const [history, setHistory] = createSignal<FindingCaseTransition[]>([])
  const [historyLoading, setHistoryLoading] = createSignal(false)
  const [historyLoaded, setHistoryLoaded] = createSignal(false)
  const [historyFailed, setHistoryFailed] = createSignal(false)
  const [operations, setOperations] = createSignal<FindingCaseOperation[]>([])
  const [operationsLoading, setOperationsLoading] = createSignal(false)
  const [operationsLoaded, setOperationsLoaded] = createSignal(false)
  const [operationsFailed, setOperationsFailed] = createSignal(false)
  const [operationsOpen, setOperationsOpen] = createSignal(false)
  const [mergeTarget, setMergeTarget] = createSignal("")
  const [mergeReason, setMergeReason] = createSignal("")
  const [splitReason, setSplitReason] = createSignal("")
  const [selectedFindings, setSelectedFindings] = createSignal<string[]>([])
  const [reverseReason, setReverseReason] = createSignal("")
  const [operationSaving, setOperationSaving] = createSignal(false)
  const assignedFindings = () => props.findings.filter((finding) => finding.id && finding.caseID === props.record.id)

  const loadHistory = async () => {
    if (historyLoaded() || historyLoading()) return
    setHistoryLoading(true)
    setHistoryFailed(false)
    try {
      setHistory(await loadFindingCaseHistory((...args) => sdk.request(...args), props.sessionID, props.record.id))
      setHistoryLoaded(true)
    } catch {
      setHistoryFailed(true)
    } finally {
      setHistoryLoading(false)
    }
  }

  const loadOperations = async () => {
    if (operationsLoaded() || operationsLoading()) return
    setOperationsLoading(true)
    setOperationsFailed(false)
    try {
      setOperations(
        await loadFindingCaseOperations((...args) => sdk.request(...args), props.sessionID, props.record.id),
      )
      setOperationsLoaded(true)
    } catch {
      setOperationsFailed(true)
    } finally {
      setOperationsLoading(false)
    }
  }

  createEffect(() => {
    props.refreshVersion
    setHistoryLoaded(false)
    setOperationsLoaded(false)
    setOperations([])
    if (operationsOpen()) untrack(() => void loadOperations())
  })

  const merge = async () => {
    const targetCaseID = mergeTarget()
    const reasonValue = mergeReason().trim()
    if (!targetCaseID || !reasonValue) return
    setOperationSaving(true)
    try {
      await mergeFindingCases((...args) => sdk.request(...args), props.sessionID, props.record.id, {
        targetCaseID,
        reason: reasonValue,
      })
      setMergeReason("")
      showToast({ title: language.t("findings.cases.mergeSaved") })
      props.onChanged()
    } catch (error) {
      showToast({
        title: language.t("findings.cases.operationFailed"),
        description: error instanceof Error ? error.message : undefined,
      })
    } finally {
      setOperationSaving(false)
    }
  }

  const split = async () => {
    const findingIDs = selectedFindings()
    const reasonValue = splitReason().trim()
    if (findingIDs.length === 0 || !reasonValue) return
    setOperationSaving(true)
    try {
      await splitFindingCase((...args) => sdk.request(...args), props.sessionID, props.record.id, {
        findingIDs,
        reason: reasonValue,
      })
      setSelectedFindings([])
      setSplitReason("")
      showToast({ title: language.t("findings.cases.splitSaved") })
      props.onChanged()
    } catch (error) {
      showToast({
        title: language.t("findings.cases.operationFailed"),
        description: error instanceof Error ? error.message : undefined,
      })
    } finally {
      setOperationSaving(false)
    }
  }

  const reverse = async (operation: FindingCaseOperation) => {
    const reasonValue = reverseReason().trim()
    if (!reasonValue) return
    setOperationSaving(true)
    try {
      await reverseFindingCaseOperation(
        (...args) => sdk.request(...args),
        props.sessionID,
        props.record.id,
        operation.id,
        reasonValue,
      )
      setReverseReason("")
      showToast({ title: language.t("findings.cases.reverseSaved") })
      props.onChanged()
    } catch (error) {
      showToast({
        title: language.t("findings.cases.operationFailed"),
        description: error instanceof Error ? error.message : undefined,
      })
    } finally {
      setOperationSaving(false)
    }
  }

  const save = async () => {
    let acceptedRiskUntil: number | undefined
    if (status() === "accepted-risk") {
      acceptedRiskUntil = expiry() ? new Date(`${expiry()}T23:59:59`).getTime() : Number.NaN
      if (!Number.isFinite(acceptedRiskUntil) || acceptedRiskUntil <= Date.now()) {
        showToast({ title: language.t("findings.cases.expiryRequired") })
        return
      }
    }

    setSaving(true)
    try {
      const updated = await updateFindingCaseStatus(
        (...args) => sdk.request(...args),
        props.sessionID,
        props.record.id,
        {
          status: status(),
          reason: reason().trim() || undefined,
          acceptedRiskUntil,
        },
      )
      props.onSaved(updated)
      showToast({ title: language.t("findings.cases.saved") })
    } catch {
      showToast({ title: language.t("findings.cases.failed") })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div class="grid gap-2 border-t border-border-weaker-base px-3 py-2 md:grid-cols-[minmax(7rem,1fr)_minmax(8rem,1.2fr)_minmax(8rem,1.2fr)_minmax(10rem,1.5fr)_auto] md:items-center">
      <div class="min-w-0">
        <code class="block truncate text-10-mono text-text-tertiary">{props.record.id.slice(0, 20)}</code>
        <span class="text-11-regular text-text-secondary">
          {props.record.findingCount} {language.t("findings.cases.findings")}
        </span>
      </div>
      <span class="text-11-regular text-text-secondary">
        {props.record.sessionCount} {language.t("findings.cases.sessions")}
      </span>
      <label class="grid min-w-0 gap-1 text-11-regular text-text-secondary">
        <span>{language.t("findings.cases.status")}</span>
        <select
          aria-label={language.t("findings.cases.status")}
          class="min-w-0 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 text-11-regular text-text-primary"
          value={status()}
          onChange={(event) => setStatus(event.currentTarget.value as FindingCaseStatus)}
        >
          <For each={CASE_STATUSES}>{(value) => <option value={value}>{statusLabel(language, value)}</option>}</For>
        </select>
      </label>
      <div class="grid min-w-0 gap-1">
        <label class="grid min-w-0 gap-1 text-11-regular text-text-secondary">
          <span>{language.t("findings.cases.reason")}</span>
          <input
            type="text"
            maxlength={2000}
            value={reason()}
            placeholder={language.t("findings.cases.reasonPlaceholder")}
            onInput={(event) => setReason(event.currentTarget.value)}
            class="min-w-0 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 text-11-regular text-text-primary"
          />
        </label>
        <Show when={status() === "accepted-risk"}>
          <label class="grid min-w-0 gap-1 text-11-regular text-text-secondary">
            <span>{language.t("findings.cases.expiry")}</span>
            <input
              type="date"
              required
              value={expiry()}
              onInput={(event) => setExpiry(event.currentTarget.value)}
              class="min-w-0 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 text-11-regular text-text-primary"
            />
          </label>
        </Show>
      </div>
      <Button size="small" variant="secondary" disabled={saving()} onClick={() => void save()}>
        {language.t("findings.cases.save")}
      </Button>
      <details class="col-span-full text-11-regular text-text-secondary">
        <summary class="cursor-pointer py-1 text-11-regular text-text-secondary">
          {language.t("findings.cases.operations")}
        </summary>
        <div class="grid gap-3 py-2 md:grid-cols-2">
          <div class="grid content-start gap-2 rounded-sm border border-border-weaker-base p-2">
            <strong class="text-text-primary">{language.t("findings.cases.merge")}</strong>
            <label class="grid gap-1">
              <span>{language.t("findings.cases.mergeTarget")}</span>
              <select
                aria-label={language.t("findings.cases.mergeTarget")}
                class="min-w-0 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 text-11-regular text-text-primary"
                value={mergeTarget()}
                onChange={(event) => setMergeTarget(event.currentTarget.value)}
              >
                <option value="">{language.t("findings.cases.mergeTargetPlaceholder")}</option>
                <For each={props.records.filter((record) => record.id !== props.record.id)}>
                  {(record) => <option value={record.id}>{record.id.slice(0, 24)}</option>}
                </For>
              </select>
            </label>
            <label class="grid gap-1">
              <span>{language.t("findings.cases.reason")}</span>
              <input
                maxlength={2000}
                value={mergeReason()}
                onInput={(event) => setMergeReason(event.currentTarget.value)}
                class="min-w-0 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 text-11-regular text-text-primary"
              />
            </label>
            <Button
              size="small"
              variant="secondary"
              disabled={operationSaving() || !mergeTarget() || !mergeReason().trim()}
              onClick={() => void merge()}
            >
              {language.t("findings.cases.mergeAction")}
            </Button>
          </div>
          <div class="grid content-start gap-2 rounded-sm border border-border-weaker-base p-2">
            <strong class="text-text-primary">{language.t("findings.cases.split")}</strong>
            <Show
              when={assignedFindings().length > 0}
              fallback={<span>{language.t("findings.cases.noSessionFindings")}</span>}
            >
              <div class="grid max-h-36 gap-1 overflow-y-auto">
                <For each={assignedFindings()}>
                  {(finding) => {
                    const findingID = finding.id!
                    return (
                      <label class="flex min-w-0 items-center gap-2">
                        <input
                          type="checkbox"
                          checked={selectedFindings().includes(findingID)}
                          disabled={!selectedFindings().includes(findingID) && selectedFindings().length >= 500}
                          onChange={(event) =>
                            setSelectedFindings((current) =>
                              event.currentTarget.checked && current.length >= 500
                                ? current
                                : event.currentTarget.checked
                                  ? [...new Set([...current, findingID])]
                                  : current.filter((id) => id !== findingID),
                            )
                          }
                        />
                        <span class="truncate">{finding.title}</span>
                      </label>
                    )
                  }}
                </For>
              </div>
            </Show>
            <label class="grid gap-1">
              <span>{language.t("findings.cases.reason")}</span>
              <input
                maxlength={2000}
                value={splitReason()}
                onInput={(event) => setSplitReason(event.currentTarget.value)}
                class="min-w-0 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 text-11-regular text-text-primary"
              />
            </label>
            <Button
              size="small"
              variant="secondary"
              disabled={operationSaving() || selectedFindings().length === 0 || !splitReason().trim()}
              onClick={() => void split()}
            >
              {language.t("findings.cases.splitAction")}
            </Button>
          </div>
        </div>
      </details>
      <details
        class="col-span-full text-11-regular text-text-secondary"
        onToggle={(event) => {
          if (event.currentTarget.open) void loadHistory()
        }}
      >
        <summary class="cursor-pointer py-1 text-11-regular text-text-secondary">
          {language.t("findings.cases.history")}
        </summary>
        <Show when={historyLoading()}>
          <p class="py-1 text-text-tertiary">{language.t("findings.cases.historyLoading")}</p>
        </Show>
        <Show when={historyFailed()}>
          <p class="py-1 text-severity-fg-high" role="alert">
            {language.t("findings.cases.historyFailed")}
          </p>
        </Show>
        <Show when={historyLoaded() && history().length === 0}>
          <p class="py-1 text-text-tertiary">{language.t("findings.cases.historyEmpty")}</p>
        </Show>
        <ol class="grid gap-1 border-l border-border-weaker-base py-1 pl-3">
          <For each={history()}>
            {(entry) => (
              <li class="grid gap-0.5">
                <span class="text-text-primary">
                  {entry.fromStatus ? statusLabel(language, entry.fromStatus) : statusLabel(language, entry.toStatus)}
                  {entry.fromStatus ? ` → ${statusLabel(language, entry.toStatus)}` : ""}
                </span>
                <span class="text-10-mono text-text-tertiary">
                  {new Date(entry.createdAt).toLocaleString()} · {language.t(`findings.cases.actor.${entry.actor}`)}
                </span>
                <Show when={entry.reason}>
                  {(value) => <span class="break-words text-text-secondary">{value()}</span>}
                </Show>
              </li>
            )}
          </For>
        </ol>
      </details>
      <details
        class="col-span-full text-11-regular text-text-secondary"
        onToggle={(event) => {
          setOperationsOpen(event.currentTarget.open)
          if (event.currentTarget.open) void loadOperations()
        }}
      >
        <summary class="cursor-pointer py-1 text-11-regular text-text-secondary">
          {language.t("findings.cases.operationHistory")}
        </summary>
        <Show when={operationsLoading()}>
          <p class="py-1 text-text-tertiary">{language.t("findings.cases.historyLoading")}</p>
        </Show>
        <Show when={operationsFailed()}>
          <p class="py-1 text-severity-fg-high" role="alert">
            {language.t("findings.cases.historyFailed")}
          </p>
        </Show>
        <Show when={operationsLoaded() && operations().length === 0}>
          <p class="py-1 text-text-tertiary">{language.t("findings.cases.operationHistoryEmpty")}</p>
        </Show>
        <ol class="grid gap-2 border-l border-border-weaker-base py-1 pl-3">
          <For each={operations()}>
            {(operation) => (
              <li class="grid gap-1">
                <span class="text-text-primary">
                  {language.t(`findings.cases.operation.${operation.kind}`)} · {operation.sourceCaseID.slice(0, 16)} →{" "}
                  {operation.targetCaseID.slice(0, 16)}
                </span>
                <span class="text-10-mono text-text-tertiary">
                  {new Date(operation.createdAt).toLocaleString()} ·{" "}
                  {language.t(`findings.cases.actor.${operation.actor}`)}
                </span>
                <span class="break-words text-text-secondary">{operation.reason}</span>
                <Show when={operation.reversedAt !== undefined}>
                  <span class="break-words text-text-tertiary">
                    {language.t("findings.cases.operationReversed")}: {operation.reversedReason}
                  </span>
                </Show>
                <Show when={operation.reversedAt === undefined}>
                  <div class="flex flex-wrap items-end gap-2">
                    <label class="grid min-w-40 flex-1 gap-1">
                      <span>{language.t("findings.cases.reverseReason")}</span>
                      <input
                        maxlength={2000}
                        value={reverseReason()}
                        onInput={(event) => setReverseReason(event.currentTarget.value)}
                        class="min-w-0 rounded-sm border border-border-weaker-base bg-bg-base px-2 py-1 text-11-regular text-text-primary"
                      />
                    </label>
                    <Button
                      size="small"
                      variant="secondary"
                      disabled={operationSaving() || !reverseReason().trim()}
                      onClick={() => void reverse(operation)}
                    >
                      {language.t("findings.cases.reverse")}
                    </Button>
                  </div>
                </Show>
              </li>
            )}
          </For>
        </ol>
      </details>
    </div>
  )
}

export function FindingCasesPanel(props: { sessionID: string; refreshKey: string; findings: Finding[] }) {
  const language = useLanguage()
  const sdk = useSDK()
  const [records, setRecords] = createSignal<FindingCase[]>([])
  const [persistedFindings, setPersistedFindings] = createSignal<Finding[]>(props.findings)
  const [refreshVersion, setRefreshVersion] = createSignal(0)
  const [loading, setLoading] = createSignal(true)
  const [loadFailed, setLoadFailed] = createSignal(false)

  createEffect(() => {
    props.refreshKey
    let disposed = false
    setLoading(true)
    setLoadFailed(false)
    const request = (...args: Parameters<typeof sdk.request>) => sdk.request(...args)
    void Promise.all([loadSessionFindingCases(request, props.sessionID), loadSessionFindings(request, props.sessionID)])
      .then(([items, findings]) => {
        if (!disposed) {
          setRecords(items)
          if (findings) setPersistedFindings(findings)
        }
      })
      .catch(() => {
        if (disposed) return
        setLoadFailed(true)
        showToast({ title: language.t("findings.cases.loadFailed") })
      })
      .finally(() => {
        if (!disposed) setLoading(false)
      })
    onCleanup(() => {
      disposed = true
    })
  })

  const refresh = async () => {
    const request = (...args: Parameters<typeof sdk.request>) => sdk.request(...args)
    const [items, findings] = await Promise.all([
      loadSessionFindingCases(request, props.sessionID),
      loadSessionFindings(request, props.sessionID),
    ])
    setRecords(items)
    if (findings) setPersistedFindings(findings)
    setRefreshVersion((value) => value + 1)
  }

  return (
    <Show when={!loading() && !loadFailed() && records().length > 0}>
      <section
        class="shrink-0 border-b border-border-weaker-base bg-bg-surface/50"
        aria-label={language.t("findings.cases.title")}
      >
        <header class="flex items-center justify-between gap-2 px-3 py-2">
          <h3 class="text-11-mono font-semibold uppercase tracking-wider text-text-secondary">
            {language.t("findings.cases.title")}
          </h3>
          <span class="text-10-mono tabular-nums text-text-tertiary">{records().length}</span>
        </header>
        <div class="max-h-96 overflow-y-auto">
          <For each={records()}>
            {(record) => (
              <FindingCaseRow
                record={record}
                records={records()}
                findings={persistedFindings()}
                sessionID={props.sessionID}
                refreshVersion={refreshVersion()}
                onSaved={(updated) =>
                  setRecords((items) => items.map((item) => (item.id === updated.id ? updated : item)))
                }
                onChanged={() =>
                  void refresh().catch(() => showToast({ title: language.t("findings.cases.loadFailed") }))
                }
              />
            )}
          </For>
        </div>
      </section>
    </Show>
  )
}
