import type { useLanguage } from "@/context/language"
import { showToast } from "@/utils/toast"

export function showRequestError(language: ReturnType<typeof useLanguage>, err: unknown) {
  showToast({
    title: language.t("common.requestFailed"),
    description: err instanceof Error ? err.message : String(err),
  })
}
