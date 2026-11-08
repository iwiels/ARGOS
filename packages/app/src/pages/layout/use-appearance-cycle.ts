import { showToast } from "@/utils/toast"
import { useLanguage, type Locale } from "@/context/language"
import { useTheme, type ColorScheme } from "@argos/ui/theme/context"

const colorSchemeOrder: ColorScheme[] = ["system", "light", "dark"]

const colorSchemeKey: Record<ColorScheme, "theme.scheme.system" | "theme.scheme.light" | "theme.scheme.dark"> = {
  system: "theme.scheme.system",
  light: "theme.scheme.light",
  dark: "theme.scheme.dark",
}

/** Theme/locale cycling used by the layout command palette. */
export function useAppearanceCycle() {
  const theme = useTheme()
  const language = useLanguage()

  const colorSchemeLabel = (scheme: ColorScheme) => language.t(colorSchemeKey[scheme])

  function cycleColorScheme(direction = 1) {
    const current = theme.colorScheme()
    const currentIndex = colorSchemeOrder.indexOf(current)
    const nextIndex =
      currentIndex === -1 ? 0 : (currentIndex + direction + colorSchemeOrder.length) % colorSchemeOrder.length
    const next = colorSchemeOrder[nextIndex]
    theme.setColorScheme(next)
    showToast({
      title: language.t("toast.scheme.title"),
      description: colorSchemeLabel(next),
    })
  }

  function setLocale(next: Locale) {
    if (next === language.locale()) return
    language.setLocale(next)
    showToast({
      title: language.t("toast.language.title"),
      description: language.t("toast.language.description", { language: language.label(next) }),
    })
  }

  function cycleLanguage(direction = 1) {
    const locales = language.locales
    const currentIndex = locales.indexOf(language.locale())
    const nextIndex = currentIndex === -1 ? 0 : (currentIndex + direction + locales.length) % locales.length
    const next = locales[nextIndex]
    if (!next) return
    setLocale(next)
  }

  return { colorSchemeOrder, colorSchemeLabel, cycleColorScheme, setLocale, cycleLanguage }
}
