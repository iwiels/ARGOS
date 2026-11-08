import { createStore } from "solid-js/store"
import { Show, For } from "solid-js"
import { Button } from "@argos/ui/button"
import { useLanguage } from "@/context/language"
import { useSDK } from "@/context/sdk"
import { showToast } from "@/utils/toast"
import { importFindings, previewFindingImport } from "./security-findings-api"
import type { FindingImportFormat, FindingImportPreview } from "@argos/core/security"

const FORMATS: { value: FindingImportFormat; label: string }[] = [
  { value: "sarif-2.1", label: "SARIF 2.1" },
  { value: "nuclei-jsonl", label: "Nuclei JSONL" },
  { value: "semgrep-json", label: "Semgrep JSON" },
  { value: "gitleaks-json", label: "Gitleaks JSON" },
  { value: "trivy-json", label: "Trivy JSON" },
  { value: "zap-json", label: "OWASP ZAP JSON" },
  { value: "burp-xml", label: "Burp XML" },
  { value: "defectdojo-generic-json", label: "DefectDojo Generic JSON" },
]

const MAX_IMPORT_BYTES = 8 * 1024 * 1024

export function FindingImportPanel(props: { sessionID: string; onImported: () => void }) {
  const sdk = useSDK()
  const language = useLanguage()
  let fileInput: HTMLInputElement | undefined
  const [state, setState] = createStore({
    expanded: false,
    format: "sarif-2.1" as FindingImportFormat,
    file: undefined as File | undefined,
    content: "",
    preview: undefined as FindingImportPreview | undefined,
    pending: false,
    error: "",
  })

  const clearPreview = () => setState({ content: "", preview: undefined, error: "" })

  const selectFile = (event: Event) => {
    const input = event.currentTarget as HTMLInputElement
    const file = input.files?.[0]
    clearPreview()
    if (!file) {
      setState("file", undefined)
      return
    }
    if (file.size > MAX_IMPORT_BYTES) {
      input.value = ""
      setState({ file: undefined, error: language.t("findings.import.sizeLimit", { limit: 8 }) })
      return
    }
    setState({ file, error: "" })
  }

  const handlePreview = async () => {
    const file = state.file
    if (!file) {
      setState("error", language.t("findings.import.noFile"))
      return
    }
    setState({ pending: true, error: "", preview: undefined })
    try {
      const content = await file.text()
      if (new TextEncoder().encode(content).byteLength > MAX_IMPORT_BYTES) {
        throw new Error(language.t("findings.import.sizeLimit", { limit: 8 }))
      }
      const preview = await previewFindingImport(
        (path, init) => sdk.request(path, init),
        props.sessionID,
        state.format,
        content,
      )
      if (state.file !== file) return
      setState({ content, preview })
    } catch (error) {
      setState("error", error instanceof Error ? error.message : language.t("findings.import.invalidFile"))
    } finally {
      setState("pending", false)
    }
  }

  const handleImport = async () => {
    const preview = state.preview
    const content = state.content
    if (!preview || !content || preview.format !== state.format) return
    setState({ pending: true, error: "" })
    try {
      const result = await importFindings(
        (path, init) => sdk.request(path, init),
        props.sessionID,
        state.format,
        content,
      )
      showToast({
        title: language.t("findings.import.success"),
        description: language.t("findings.import.successCount", { count: result.importedCount }),
      })
      if (fileInput) fileInput.value = ""
      setState({ expanded: false, file: undefined, content: "", preview: undefined })
      props.onImported()
    } catch (error) {
      setState("error", error instanceof Error ? error.message : language.t("findings.import.saveFailed"))
    } finally {
      setState("pending", false)
    }
  }

  return (
    <section class="shrink-0 border-b border-border-weaker-base bg-bg-base/70 px-4 py-2">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="min-w-0">
          <div class="text-xs font-medium text-text-primary">{language.t("findings.import.title")}</div>
          <div class="text-11-regular text-text-tertiary">{language.t("findings.import.description")}</div>
        </div>
        <Button
          size="small"
          variant="secondary"
          aria-expanded={state.expanded}
          onClick={() => setState("expanded", !state.expanded)}
        >
          {state.expanded ? language.t("findings.import.close") : language.t("findings.import.open")}
        </Button>
      </div>
      <Show when={state.expanded}>
        <div class="mt-3 grid gap-3 border-t border-border-weaker-base pt-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] md:items-end">
          <label class="grid min-w-0 gap-1.5 text-xs text-text-secondary">
            <span>{language.t("findings.import.format")}</span>
            <select
              class="h-8 rounded-sm border border-border-weaker-base bg-bg-base px-2 text-xs text-text-primary outline-none focus:border-border-strong"
              value={state.format}
              onChange={(event) => {
                clearPreview()
                setState("format", event.currentTarget.value as FindingImportFormat)
              }}
            >
              <For each={FORMATS}>{(format) => <option value={format.value}>{format.label}</option>}</For>
            </select>
          </label>
          <label class="grid min-w-0 gap-1.5 text-xs text-text-secondary">
            <span>{language.t("findings.import.fileLabel", { limit: 8 })}</span>
            <input
              ref={fileInput}
              type="file"
              accept=".sarif,.json,.jsonl,.xml,application/json,application/xml,text/xml"
              onChange={selectFile}
              class="min-w-0 text-xs text-text-primary file:mr-2 file:rounded-sm file:border file:border-border-weaker-base file:bg-bg-surface file:px-2 file:py-1 file:text-xs file:text-text-secondary"
            />
          </label>
          <Button size="small" variant="secondary" disabled={state.pending || !state.file} onClick={handlePreview}>
            {state.pending ? language.t("findings.import.validating") : language.t("findings.import.preview")}
          </Button>
        </div>
        <Show when={state.preview}>
          {(preview) => (
            <div class="mt-3 border-t border-border-weaker-base pt-3" aria-live="polite">
              <p class="text-xs text-text-primary">
                {language.t("findings.import.summary", { count: preview().findings.length })}
              </p>
              <Show when={preview().warnings.length > 0}>
                <ul class="mt-2 list-disc space-y-1 pl-5 text-xs text-severity-fg-medium">
                  <For each={preview().warnings}>{(warning) => <li>{warning}</li>}</For>
                </ul>
              </Show>
              <ul class="mt-2 max-h-36 overflow-auto divide-y divide-border-weaker-base text-xs">
                <For each={preview().findings.slice(0, 8)}>
                  {(finding) => (
                    <li class="flex flex-wrap justify-between gap-x-4 gap-y-1 py-1.5">
                      <span class="min-w-0 break-words text-text-primary">{finding.title}</span>
                      <span class="shrink-0 font-mono text-11-mono text-text-tertiary">
                        {finding.severity}
                        {finding.target ? ` · ${finding.target}` : ""}
                      </span>
                    </li>
                  )}
                </For>
              </ul>
              <Show when={preview().findings.length > 8}>
                <p class="mt-1 text-11-regular text-text-tertiary">
                  {language.t("findings.import.more", { count: preview().findings.length - 8 })}
                </p>
              </Show>
              <div class="mt-3 flex flex-wrap items-center gap-2">
                <Button
                  size="small"
                  variant="primary"
                  disabled={state.pending || preview().findings.length === 0 || preview().format !== state.format}
                  onClick={handleImport}
                >
                  {state.pending ? language.t("findings.import.saving") : language.t("findings.import.save")}
                </Button>
                <span class="text-11-regular text-text-tertiary">{language.t("findings.import.observedOnly")}</span>
              </div>
            </div>
          )}
        </Show>
        <Show when={state.error}>
          <p class="mt-3 text-xs text-severity-fg-high" role="alert">
            {state.error}
          </p>
        </Show>
      </Show>
    </section>
  )
}
