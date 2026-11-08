import { execFile } from "node:child_process"
import { stat } from "node:fs/promises"
import { writeFile } from "node:fs/promises"
import { basename, resolve } from "node:path"
import { app, BrowserWindow, Notification, clipboard, dialog, ipcMain, safeStorage, shell } from "electron"
import type { IpcMainEvent, IpcMainInvokeEvent } from "electron"
import type { DesktopMenuAction } from "@argos/app/desktop-menu"

import type { FatalRendererError, ServerReadyData, TitlebarTheme } from "../preload/types"
import { runDesktopMenuAction } from "./desktop-menu-actions"
import { assertAttachmentBudget, createPickedFileAuthorizations } from "./attachment-picker"
import { isSafeExternalUrl } from "./safe-external-url"
import {
  canUseSecurePasswordStorage,
  protectServerPasswords,
  revealServerPasswords,
  SERVER_PASSWORD_MARK,
  SECURE_STORAGE_UNAVAILABLE,
  type PasswordCrypt,
} from "./secure-fields"
import { getStore } from "./store"
import { deleteAuthProfile, listAuthProfiles, saveAuthProfile } from "./auth-vault"
import { getPinchZoomEnabled, setPinchZoomEnabled, setTitlebar, updateTitlebar } from "./windows"
import type { UpdaterController } from "./updater-controller"
import { createUpdaterSubscriptions } from "./updater-subscriptions"

const pickerFilters = (ext?: string[]) => {
  if (!ext || ext.length === 0) return undefined
  return [{ name: "Files", extensions: ext }]
}

const pickedFiles = createPickedFileAuthorizations()

/**
 * Persiste un artefacto de reporte donde el usuario lo indique.
 *
 * El nombre de archivo que propone el renderer ya trae la extensión del
 * formato; el diálogo sólo confirma la ubicación.
 */
async function writeExportedArtifact(
  payload: { filename: string; contentBase64: string },
  label: string,
  extensions: string[],
): Promise<{ path: string } | null> {
  const result = await dialog.showSaveDialog({
    title: `Export ${label}`,
    defaultPath: payload.filename,
    filters: extensions.length > 0 ? [{ name: label, extensions }] : undefined,
  })
  if (result.canceled || !result.filePath) return null
  await writeFile(result.filePath, Buffer.from(payload.contentBase64, "base64"))
  return { path: result.filePath }
}

// Closed set of "open with" identifiers offered by the renderer UI (see the
// MAC_APPS / WINDOWS_APPS / LINUX_APPS tables in
// packages/app/src/components/session/session-header.tsx). The main process
// must not trust arbitrary strings from the renderer as an executable name -
// only these known identifiers are allowed to reach `execFile`.
const ALLOWED_OPEN_WITH_APPS = new Set([
  "Visual Studio Code",
  "Cursor",
  "Zed",
  "TextMate",
  "Antigravity",
  "Terminal",
  "iTerm",
  "Ghostty",
  "Warp",
  "Xcode",
  "Android Studio",
  "Sublime Text",
  "code",
  "cursor",
  "zed",
  "powershell",
])

// `open-path` has no renderer-independent notion of "known project
// directories" to check against (the main process does not track project
// state), so the best available defense-in-depth is: normalize/resolve the
// path and require it to already exist as a directory. This blocks path
// traversal tricks, embedded NUL bytes, and - critically - prevents
// `shell.openPath` from being used to *launch* an arbitrary file/executable,
// since it only ever legitimately receives project directories from the UI.
async function resolveOpenPathTarget(rawPath: string): Promise<string> {
  if (typeof rawPath !== "string" || rawPath.length === 0 || rawPath.includes("\0")) {
    throw new Error("Invalid path for open-path")
  }
  const resolved = resolve(rawPath)
  const info = await stat(resolved).catch(() => null)
  if (!info || !info.isDirectory()) {
    throw new Error(`Refusing to open non-directory path: ${rawPath}`)
  }
  return resolved
}

type Deps = {
  killSidecar: () => Promise<void> | void
  relaunch: () => void
  awaitInitialization: () => Promise<ServerReadyData>
  refreshRuntimeTools: () => Promise<NonNullable<ServerReadyData["tools"]> | null>
  consumeInitialDeepLinks: () => Promise<string[]> | string[]
  getDefaultServerUrl: () => Promise<string | null> | string | null
  setDefaultServerUrl: (url: string | null) => Promise<void> | void
  getDisplayBackend: () => Promise<string | null>
  setDisplayBackend: (backend: string | null) => Promise<void> | void
  checkAppExists: (appName: string) => Promise<boolean> | boolean
  resolveAppPath: (appName: string) => Promise<string | null>
  updater: UpdaterController
  showUpdater: () => Promise<void> | void
  setBackgroundColor: (color: string) => void
  exportDebugLogs: () => Promise<string>
  recordFatalRendererError: (error: FatalRendererError) => Promise<void> | void
}

export function registerIpcHandlers(deps: Deps) {
  const updaterSubscriptions = createUpdaterSubscriptions()
  app.once("will-quit", () => updaterSubscriptions.clear())

  ipcMain.handle("kill-sidecar", () => deps.killSidecar())
  ipcMain.handle("await-initialization", () => deps.awaitInitialization())
  ipcMain.handle("refresh-runtime-tools", () => deps.refreshRuntimeTools())
  ipcMain.handle("consume-initial-deep-links", () => deps.consumeInitialDeepLinks())
  ipcMain.handle("get-default-server-url", () => deps.getDefaultServerUrl())
  ipcMain.handle("set-default-server-url", (_event: IpcMainInvokeEvent, url: string | null) =>
    deps.setDefaultServerUrl(url),
  )
  ipcMain.handle("get-display-backend", () => deps.getDisplayBackend())
  ipcMain.handle("set-display-backend", (_event: IpcMainInvokeEvent, backend: string | null) =>
    deps.setDisplayBackend(backend),
  )
  ipcMain.handle("check-app-exists", (_event: IpcMainInvokeEvent, appName: string) => deps.checkAppExists(appName))
  ipcMain.handle("resolve-app-path", (_event: IpcMainInvokeEvent, appName: string) => deps.resolveAppPath(appName))
  ipcMain.handle("updater-subscribe", (event) => {
    const id = event.sender.id
    updaterSubscriptions.set(
      id,
      deps.updater.subscribe((state) => {
        if (event.sender.isDestroyed()) return updaterSubscriptions.delete(id)
        event.sender.send("updater-state", state)
      }),
    )
    event.sender.once("destroyed", () => updaterSubscriptions.delete(id))
  })
  ipcMain.handle("updater-unsubscribe", (event) => updaterSubscriptions.delete(event.sender.id))
  ipcMain.handle("updater-check", () => deps.updater.check())
  ipcMain.handle("updater-install", () => deps.updater.install())
  ipcMain.handle("set-background-color", (_event: IpcMainInvokeEvent, color: string) => deps.setBackgroundColor(color))
  ipcMain.handle("export-debug-logs", () => deps.exportDebugLogs())
  ipcMain.handle("record-fatal-renderer-error", (_event: IpcMainInvokeEvent, error: FatalRendererError) =>
    deps.recordFatalRendererError(error),
  )
  ipcMain.handle("auth-profile-list", (_event: IpcMainInvokeEvent, sessionID: string) => listAuthProfiles(sessionID))
  ipcMain.handle("auth-profile-save", (_event: IpcMainInvokeEvent, input: Parameters<typeof saveAuthProfile>[0]) =>
    saveAuthProfile(input),
  )
  ipcMain.handle("auth-profile-delete", (_event: IpcMainInvokeEvent, sessionID: string, id: string) =>
    deleteAuthProfile(sessionID, id),
  )
  const ALLOWED_STORES = new Set([
    "settings",
    "window-state",
    "recent-projects",
    "auth-cache",
    "opencode.settings",
    "opencode.global.dat",
    "default.dat",
  ])
  const sanitizeStoreName = (name: string): string => {
    const clean = basename(name).replace(/[^a-zA-Z0-9_.-]/g, "")
    if (!clean || (!ALLOWED_STORES.has(clean) && !clean.endsWith(".settings") && !clean.endsWith(".dat"))) {
      throw new Error(`Invalid or unauthorized store name: ${name}`)
    }
    return clean
  }

  // Server credentials are encrypted with the OS-backed Electron store.
  // Linux's basic_text fallback is deliberately rejected because its key is
  // not protected by the desktop keyring.
  const serverPasswordCrypt: PasswordCrypt = {
    encrypt(plain) {
      try {
        if (
          !canUseSecurePasswordStorage({
            platform: process.platform,
            available: safeStorage.isEncryptionAvailable(),
            backend: process.platform === "linux" ? safeStorage.getSelectedStorageBackend() : undefined,
          })
        ) {
          throw new Error(SECURE_STORAGE_UNAVAILABLE)
        }
        return SERVER_PASSWORD_MARK + safeStorage.encryptString(plain).toString("base64")
      } catch {
        throw new Error(SECURE_STORAGE_UNAVAILABLE)
      }
    },
    decrypt(stored) {
      try {
        return safeStorage.decryptString(Buffer.from(stored.slice(SERVER_PASSWORD_MARK.length), "base64"))
      } catch {
        return null
      }
    },
  }
  const isServerListBlob = (name: string, key: string) => name === "opencode.global.dat" && key === "server"

  ipcMain.handle("store-get", (_event: IpcMainInvokeEvent, name: string, key: string) => {
    const safeName = sanitizeStoreName(name)
    const store = getStore(safeName)
    const value = store.get(key)
    if (value === undefined || value === null) return null
    if (isServerListBlob(name, key)) {
      const serialized = typeof value === "string" ? value : JSON.stringify(value)
      const protectedValue = protectServerPasswords(JSON.parse(serialized), serverPasswordCrypt)
      const protectedSerialized = JSON.stringify(protectedValue)
      if (protectedSerialized !== serialized) store.set(key, protectedSerialized)
      return JSON.stringify(revealServerPasswords(protectedValue, serverPasswordCrypt))
    }
    try {
      return typeof value === "string" ? value : JSON.stringify(value)
    } catch {
      return null
    }
  })
  ipcMain.handle("store-set", (_event: IpcMainInvokeEvent, name: string, key: string, value: string) => {
    let payload = value
    if (typeof value === "string" && isServerListBlob(name, key)) {
      payload = JSON.stringify(protectServerPasswords(JSON.parse(value), serverPasswordCrypt))
    }
    getStore(sanitizeStoreName(name)).set(key, payload)
  })
  ipcMain.handle("store-delete", (_event: IpcMainInvokeEvent, name: string, key: string) => {
    getStore(sanitizeStoreName(name)).delete(key)
  })
  ipcMain.handle("store-clear", (_event: IpcMainInvokeEvent, name: string) => {
    getStore(sanitizeStoreName(name)).clear()
  })
  ipcMain.handle("store-keys", (_event: IpcMainInvokeEvent, name: string) => {
    const store = getStore(sanitizeStoreName(name))
    return Object.keys(store.store)
  })
  ipcMain.handle("store-length", (_event: IpcMainInvokeEvent, name: string) => {
    const store = getStore(sanitizeStoreName(name))
    return Object.keys(store.store).length
  })

  ipcMain.handle(
    "open-directory-picker",
    async (_event: IpcMainInvokeEvent, opts?: { multiple?: boolean; title?: string; defaultPath?: string }) => {
      const result = await dialog.showOpenDialog({
        properties: ["openDirectory", ...(opts?.multiple ? ["multiSelections" as const] : []), "createDirectory"],
        title: opts?.title ?? "Choose a folder",
        defaultPath: opts?.defaultPath,
      })
      if (result.canceled) return null
      return opts?.multiple ? result.filePaths : result.filePaths[0]
    },
  )

  ipcMain.handle(
    "open-file-picker",
    async (
      event: IpcMainInvokeEvent,
      opts?: { multiple?: boolean; title?: string; defaultPath?: string; extensions?: string[] },
    ) => {
      const result = await dialog.showOpenDialog({
        properties: ["openFile", ...(opts?.multiple ? ["multiSelections" as const] : [])],
        title: opts?.title ?? "Choose a file",
        defaultPath: opts?.defaultPath,
        filters: pickerFilters(opts?.extensions),
      })
      if (result.canceled) return null
      const files = await Promise.all(
        result.filePaths.map(async (filePath) => ({
          path: filePath,
          name: basename(filePath),
          size: (await stat(filePath)).size,
        })),
      )
      assertAttachmentBudget(files)
      const token = pickedFiles.add(event.sender.id, result.filePaths)
      return { token, files }
    },
  )

  ipcMain.handle("read-picked-file", async (event: IpcMainInvokeEvent, token: string, filePath: string) => {
    return pickedFiles.read(event.sender.id, token, filePath)
  })

  ipcMain.handle("release-picked-files", (event: IpcMainInvokeEvent, token: string) => {
    pickedFiles.release(event.sender.id, token)
  })

  ipcMain.handle(
    "save-file-picker",
    async (_event: IpcMainInvokeEvent, opts?: { title?: string; defaultPath?: string }) => {
      const result = await dialog.showSaveDialog({
        title: opts?.title ?? "Save file",
        defaultPath: opts?.defaultPath,
      })
      if (result.canceled) return null
      return result.filePath ?? null
    },
  )

  /**
   * Exporta el informe de auditoría a PDF.
   *
   * El PDF lo renderiza el backend (server-side, con metadata, portada e
   * índice); el proceso principal sólo lo persiste donde el usuario lo
   * indique. El contenido llega en base64 porque el PDF es binario.
   */
  ipcMain.handle(
    "report.exportPdf",
    async (_event: IpcMainInvokeEvent, payload: { filename: string; contentBase64: string }) => {
      return writeExportedArtifact(payload, "PDF", ["pdf"])
    },
  )

  /** Igual que `report.exportPdf`, para el resto de los formatos de export. */
  ipcMain.handle(
    "report.exportFile",
    async (
      _event: IpcMainInvokeEvent,
      payload: { filename: string; contentBase64: string; label?: string; extensions?: string[] },
    ) => {
      return writeExportedArtifact(payload, payload.label ?? "File", payload.extensions ?? [])
    },
  )

  ipcMain.on("open-link", (_event: IpcMainEvent, url: string) => {
    if (!isSafeExternalUrl(url)) return
    void shell.openExternal(url)
  })

  ipcMain.handle("open-path", async (_event: IpcMainInvokeEvent, path: string, app?: string) => {
    const target = await resolveOpenPathTarget(path)

    if (!app) return shell.openPath(target)

    if (!ALLOWED_OPEN_WITH_APPS.has(app)) {
      throw new Error(`Unauthorized app for open-path: ${app}`)
    }

    // On Windows the executable location depends on what is installed, so it
    // must be resolved from the validated identifier here in the main
    // process (never trust a pre-resolved executable path from the
    // renderer). On macOS/Linux the identifier itself is what's exec'd/opened.
    const resolvedApp = process.platform === "win32" ? await deps.resolveAppPath(app) : app
    if (!resolvedApp) return shell.openPath(target)

    await new Promise<void>((resolve, reject) => {
      // The resolved app is a validated executable path, so it is spawned
      // directly - routing through `cmd /c start` would let metacharacters in
      // paths break out of argument quoting.
      const [cmd, args] =
        process.platform === "darwin"
          ? (["open", ["-a", resolvedApp, target]] as const)
          : ([resolvedApp, [target]] as const)
      execFile(cmd, args, { windowsHide: true }, (err) => (err ? reject(err) : resolve()))
    })
  })

  ipcMain.handle("read-clipboard-image", () => {
    const image = clipboard.readImage()
    if (image.isEmpty()) return null
    const buffer = image.toPNG().buffer
    const size = image.getSize()
    return { buffer, width: size.width, height: size.height }
  })

  ipcMain.on("show-notification", (_event: IpcMainEvent, title: string, body?: string) => {
    new Notification({ title, body }).show()
  })

  ipcMain.handle("get-window-count", () => BrowserWindow.getAllWindows().length)

  ipcMain.handle("get-window-focused", (event: IpcMainInvokeEvent) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    return win?.isFocused() ?? false
  })

  ipcMain.handle("set-window-focus", (event: IpcMainInvokeEvent) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    win?.focus()
  })

  ipcMain.handle("show-window", (event: IpcMainInvokeEvent) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    win?.show()
  })

  ipcMain.on("relaunch", () => {
    deps.relaunch()
  })

  ipcMain.handle("get-zoom-factor", (event: IpcMainInvokeEvent) => event.sender.getZoomFactor())
  ipcMain.handle("set-zoom-factor", (event: IpcMainInvokeEvent, factor: number) => {
    event.sender.setZoomFactor(factor)
    const win = BrowserWindow.fromWebContents(event.sender)
    if (!win) return
    updateTitlebar(win)
  })
  ipcMain.handle("get-pinch-zoom-enabled", () => getPinchZoomEnabled())
  ipcMain.handle("set-pinch-zoom-enabled", (_event: IpcMainInvokeEvent, enabled: boolean) => {
    setPinchZoomEnabled(enabled)
  })
  ipcMain.handle("set-titlebar", (event: IpcMainInvokeEvent, theme: TitlebarTheme) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    if (!win) return
    setTitlebar(win, theme)
  })
  ipcMain.handle("run-desktop-menu-action", (event: IpcMainInvokeEvent, action: DesktopMenuAction) => {
    runDesktopMenuAction(BrowserWindow.fromWebContents(event.sender), action, {
      checkForUpdates: () => void deps.showUpdater(),
      relaunch: deps.relaunch,
    })
  })
}

export function sendMenuCommand(win: BrowserWindow, id: string) {
  win.webContents.send("menu-command", id)
}

export function sendDeepLinks(win: BrowserWindow, urls: string[]) {
  win.webContents.send("deep-link", urls)
}
