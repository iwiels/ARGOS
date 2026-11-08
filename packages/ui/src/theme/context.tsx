// @refresh reload

import { createEffect, onMount } from "solid-js"
import { createStore } from "solid-js/store"
import { makeEventListener } from "@solid-primitives/event-listener"
import { createSimpleContext } from "../context/helper"

export type ColorScheme = "light" | "dark" | "system"

const STORAGE_KEYS = {
  COLOR_SCHEME: "argos-color-scheme",
} as const

// Valores únicos del theme-color meta. El preload (argos-theme-preload.js)
// hardcodea estos mismos valores por ser un script standalone anti-FOUC.
// Deben coincidir con --bg-base de theme.css (dark: #030712 / light: #fafafa).
const THEME_COLOR = {
  DARK: "#121212",
  LIGHT: "#fafafa",
} as const

function getSystemMode(): "light" | "dark" {
  if (typeof window !== "object") return "light"
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
}

function applyMode(mode: "light" | "dark") {
  document.documentElement.dataset.colorScheme = mode
  document.documentElement.classList.toggle("dark", mode === "dark")
  document.documentElement.classList.toggle("light", mode === "light")
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute("content", mode === "dark" ? THEME_COLOR.DARK : THEME_COLOR.LIGHT)
}

function read(key: string) {
  if (typeof localStorage !== "object") return null
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, value: string) {
  if (typeof localStorage !== "object") return
  try {
    localStorage.setItem(key, value)
  } catch {}
}

function resolveMode(scheme: ColorScheme): "light" | "dark" {
  if (scheme === "light") return "light"
  if (scheme === "dark") return "dark"
  return getSystemMode()
}

export const { use: useTheme, provider: ThemeProvider } = createSimpleContext({
  name: "Theme",
  init: (props: { defaultTheme?: string; onThemeApplied?: (theme: unknown, mode: "light" | "dark") => void }) => {
    const savedScheme = ((read(STORAGE_KEYS.COLOR_SCHEME) ??
      props.defaultTheme ??
      "system") as ColorScheme)
    const [store, setStore] = createStore<{
      colorScheme: ColorScheme
      mode: "light" | "dark"
      preview: ColorScheme | null
    }>({
      colorScheme: savedScheme,
      mode: resolveMode(savedScheme),
      preview: null,
    })

    onMount(() => {
      makeEventListener(window, "storage", (e: StorageEvent) => {
        if (e.key === STORAGE_KEYS.COLOR_SCHEME && e.newValue) {
          setStore("colorScheme", e.newValue as ColorScheme)
          setStore("preview", null)
          setStore("mode", resolveMode(e.newValue as ColorScheme))
        }
      })

      const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)")
      const onMedia = () => {
        if (store.colorScheme !== "system") return
        setStore("mode", getSystemMode())
      }
      makeEventListener(mediaQuery, "change", onMedia)
    })

    createEffect(() => {
      const effective = store.preview === null ? store.mode : resolveMode(store.preview)
      applyMode(effective)
      props.onThemeApplied?.(null, effective)
    })

    const setColorScheme = (scheme: ColorScheme) => {
      write(STORAGE_KEYS.COLOR_SCHEME, scheme)
      setStore("colorScheme", scheme)
      setStore("preview", null)
      setStore("mode", resolveMode(scheme))
    }

    return {
      colorScheme: () => store.preview ?? store.colorScheme,
      mode: () => (store.preview === null ? store.mode : resolveMode(store.preview)),
      setColorScheme,
      previewColorScheme: (scheme: ColorScheme) => setStore("preview", scheme),
      cancelPreview: () => setStore("preview", null),
    }
  },
})
