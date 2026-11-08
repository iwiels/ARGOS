import Store from "electron-store"
import electron from "electron"
import { copyFileSync, existsSync } from "node:fs"
import { join } from "node:path"

import { LEGACY_SETTINGS_STORE, SETTINGS_STORE } from "./store-keys"

const cache = new Map<string, Store>()

// We cannot instantiate the electron-store at module load time because
// module import hoisting causes this to run before app.setPath("userData", ...)
// in index.ts has executed, which would result in files being written to the default directory
// (e.g. bad: %APPDATA%\@argos\desktop\argos.settings vs good: %APPDATA%\ai.argos.desktop.dev\argos.settings).
export function getStore(name = SETTINGS_STORE) {
  const cached = cache.get(name)
  if (cached) return cached

  const userData = electron.app.getPath("userData")
  if (name === SETTINGS_STORE) {
    const primary = join(userData, SETTINGS_STORE)
    const legacy = join(userData, LEGACY_SETTINGS_STORE)
    if (!existsSync(primary) && existsSync(legacy)) {
      try {
        copyFileSync(legacy, primary)
      } catch {}
    }
  }

  const next = new Store({
    name,
    cwd: userData,
    fileExtension: "",
    accessPropertiesByDotNotation: false,
  })
  cache.set(name, next)
  return next
}
