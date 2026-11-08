import { Persist, persisted } from "@/utils/persist"
import { createStore } from "solid-js/store"

export interface ReportMeta {
  legalName: string
  classification: string
  leadAuditor: string
  logoDataUrl: string
}

export const REPORT_META_DEFAULTS: ReportMeta = {
  legalName: "",
  classification: "",
  leadAuditor: "",
  logoDataUrl: "",
}

export const LOGO_MAX_BYTES = 300 * 1024

export function reportMetaTarget(worktree: string) {
  return Persist.workspace(worktree || "local", "report-meta")
}

export function createReportMetaStore(worktree: string) {
  const [meta, setMeta] = createStore<ReportMeta>({ ...REPORT_META_DEFAULTS })
  const ready = persisted(reportMetaTarget(worktree), [meta, setMeta])
  return { meta, setMeta, ready }
}

export async function readLogoAsDataUrl(file: File): Promise<string> {
  if (file.size > LOGO_MAX_BYTES) throw new Error("logo-too-large")
  if (!file.type.startsWith("image/")) throw new Error("logo-not-image")
  return await new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ""))
    reader.onerror = () => reject(reader.error ?? new Error("logo-read-failed"))
    reader.readAsDataURL(file)
  })
}
