import { randomUUID } from "node:crypto"
import { mkdirSync, rmSync } from "node:fs"
import * as http from "node:http"
import { createServer } from "node:net"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { getCACertificates, setDefaultCACertificates } from "node:tls"
import type { Event } from "electron"
import { app, BrowserWindow } from "electron"

import { Deferred, Effect, Fiber } from "effect"
import contextMenu from "electron-context-menu"

import type { ServerReadyData } from "../preload/types"
import { checkAppExists, resolveAppPath } from "./apps"
import { CHANNEL } from "./constants"
import { registerIpcHandlers, sendDeepLinks, sendMenuCommand } from "./ipc"
import { forwardInitializationFailure } from "./initialization"
import { exportDebugLogs, initCrashReporter, initLogging, startNetLog, write as writeLog } from "./logging"
import { createMenu } from "./menu"
import {
  getDefaultServerUrl,
  ensureNativeLinuxWorkerImage,
  preferAppEnv,
  setDefaultServerUrl,
  spawnLocalServer,
  linuxFirstRuntimePreflight,
  nativeRuntimePreflight,
  type SidecarListener,
} from "./server"
import { setupAutoUpdater, showUpdaterDialog } from "./updater"
import { WSL_MULTI_SERVER_MANAGEMENT_ENABLED } from "../shared/feature-flags"
import {
  createMainWindow,
  registerRendererProtocol,
  setRelaunchHandler,
  setBackgroundColor,
  setDockIcon,
} from "./windows"
import { createWslServersController } from "./wsl/servers"
import { registerWslIpcHandlers } from "./wsl/ipc"
import { probePrimaryWslRuntimeTools, spawnPrimaryWslSidecar, spawnWslSidecar } from "./wsl/sidecar"

const APP_NAMES: Record<string, string> = {
  dev: "Argos Dev",
  beta: "Argos Beta",
  prod: "Argos",
}
const APP_IDS: Record<string, string> = {
  dev: "ai.argos.desktop.dev",
  beta: "ai.argos.desktop.beta",
  prod: "ai.argos.desktop",
}
const PROTOCOLS = ["argos"] as const
const TEST_ONBOARDING = process.env.ARGOS_TEST_ONBOARDING === "1" || process.env.OPENCODE_TEST_ONBOARDING === "1"
const jsCallStackFeature = "DocumentPolicyIncludeJSCallStacksInCrashReports"

let logger: ReturnType<typeof initLogging>
let mainWindow: BrowserWindow | null = null
let server: SidecarListener | null = null

const pendingDeepLinks: string[] = []

function useEnvProxy() {
  try {
    // Electron 41.2 runs Node 24.14.1; latest @types/node@24 is 24.12.2.
    ;(http as any).setGlobalProxyFromEnv()
  } catch (error) {
    logger.warn("failed to load proxy environment", error)
  }
}

function isDeepLink(url: string) {
  return PROTOCOLS.some((scheme) => url.startsWith(`${scheme}://`))
}

function emitDeepLinks(urls: string[]) {
  if (urls.length === 0) return
  pendingDeepLinks.push(...urls)
  if (mainWindow) sendDeepLinks(mainWindow, urls)
}

async function killSidecar() {
  if (!server) return
  const current = server
  server = null
  await current.stop()
}

function ensureLoopbackNoProxy() {
  const loopback = ["127.0.0.1", "localhost", "::1"]
  const upsert = (key: string) => {
    const items = (process.env[key] ?? "")
      .split(",")
      .map((value: string) => value.trim())
      .filter((value: string) => Boolean(value))

    for (const host of loopback) {
      if (items.some((value: string) => value.toLowerCase() === host)) continue
      items.push(host)
    }

    process.env[key] = items.join(",")
  }

  upsert("NO_PROXY")
  upsert("no_proxy")
}

const main = Effect.gen(function* () {
  contextMenu({ showSaveImageAs: true, showLookUpSelection: false, showSearchWithGoogle: false })

  // on macOS apps run in `/` which can cause issues with ripgrep
  try {
    process.chdir(homedir())
  } catch {}

  process.env.ARGOS_DISABLE_EMBEDDED_WEB_UI = "true"
  process.env.OPENCODE_DISABLE_EMBEDDED_WEB_UI = "true"

  const appId = app.isPackaged ? APP_IDS[CHANNEL] : APP_IDS.dev
  const onboardingTestRoot = ((): string | undefined => {
    if (!TEST_ONBOARDING) return

    const root = join(tmpdir(), `argos-onboarding-${randomUUID()}`)
    rmSync(root, { recursive: true, force: true })
    ;["data", "config", "cache", "state", "desktop", "session"].forEach((dir) =>
      mkdirSync(join(root, dir), { recursive: true }),
    )
    process.env.ARGOS_DB = ":memory:"
    process.env.OPENCODE_DB = ":memory:"
    process.env.XDG_DATA_HOME = join(root, "data")
    process.env.XDG_CONFIG_HOME = join(root, "config")
    process.env.XDG_CACHE_HOME = join(root, "cache")
    process.env.XDG_STATE_HOME = join(root, "state")
    return root
  })()
  const userDataPath = onboardingTestRoot ? join(onboardingTestRoot, "desktop") : join(app.getPath("appData"), appId)
  app.setName(app.isPackaged ? APP_NAMES[CHANNEL] : APP_NAMES.dev)
  app.setAppUserModelId(appId)
  app.setPath("userData", userDataPath)
  if (onboardingTestRoot) app.setPath("sessionData", join(onboardingTestRoot, "session"))
  logger = initLogging()
  initCrashReporter()

  const wslServers = createWslServersController(
    app.getVersion(),
    async (distro) => {
      logger.log("spawning wsl sidecar", { distro })
      return spawnWslSidecar(distro, {
        onLine: (line) => logger.log("wsl sidecar", { distro, stream: line.stream, text: line.text }),
      })
    },
    {
      logger: {
        log: (message, meta) => logger.log(message, meta),
        error: (message, meta) => logger.error(message, meta),
      },
    },
  )
  const stopSidecars = async () => {
    await killSidecar()
    wslServers.stopAll()
  }
  const relaunch = () => {
    void stopSidecars().finally(() => {
      if (!app.isPackaged) {
        const win = BrowserWindow.getAllWindows()[0]
        if (win) {
          win.reload()
          return
        }
      }
      app.relaunch()
      app.exit(0)
    })
  }

  try {
    setDefaultCACertificates([...new Set([...getCACertificates("default"), ...getCACertificates("system")])])
  } catch (error) {
    logger.warn("failed to load system certificates", error)
  }

  logger.log("app starting", {
    version: app.getVersion(),
    packaged: app.isPackaged,
    onboardingTest: Boolean(onboardingTestRoot),
  })

  ensureLoopbackNoProxy()
  useEnvProxy()
  app.commandLine.appendSwitch("proxy-bypass-list", "<-loopback>")
  const features = app.commandLine.getSwitchValue("enable-features")
  app.commandLine.appendSwitch("enable-features", features ? `${jsCallStackFeature},${features}` : jsCallStackFeature)
  if (!app.isPackaged) app.commandLine.appendSwitch("remote-debugging-port", "9222")

  if (!app.requestSingleInstanceLock()) {
    app.quit()
    return
  }

  preferAppEnv(app.getPath("userData"))

  app.on("second-instance", (_event: Event, argv: string[]) => {
    const urls = argv.filter((arg: string) => isDeepLink(arg))
    if (urls.length) {
      logger.log("deep link received via second-instance", { urls })
      emitDeepLinks(urls)
    }
    if (mainWindow) {
      mainWindow.show()
      mainWindow.focus()
    }
  })

  app.on("open-url", (event: Event, url: string) => {
    event.preventDefault()
    logger.log("deep link received via open-url", { url })
    emitDeepLinks([url])
  })

  app.on("before-quit", () => {
    void stopSidecars()
  })

  app.on("child-process-gone", (_event, details) => {
    writeLog("utility", "child process gone", { details }, "error")
  })

  app.on("render-process-gone", (_event, webContents, details) => {
    writeLog("window", "app render process gone", { url: webContents.getURL(), details }, "error")
  })

  setRelaunchHandler(() => {
    relaunch()
  })

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, () => {
      void stopSidecars().finally(() => app.exit(0))
    })
  }

  const serverReady = Deferred.makeUnsafe<ServerReadyData, unknown>()

  yield* Effect.promise(() => app.whenReady())

  for (const scheme of PROTOCOLS) app.setAsDefaultProtocolClient(scheme)
  registerRendererProtocol()
  setDockIcon()
  const updater = setupAutoUpdater(stopSidecars)
  registerIpcHandlers({
    killSidecar: () => killSidecar(),
    relaunch,
    awaitInitialization: Effect.fnUntraced(
      function* () {
        logger.log("awaiting server ready")
        const res = yield* Deferred.await(serverReady)
        logger.log("server ready", { url: res.url })
        return res
      },
      (e) => Effect.runPromise(e),
    ),
    refreshRuntimeTools: () => probePrimaryWslRuntimeTools(),
    consumeInitialDeepLinks: () => pendingDeepLinks.splice(0),
    getDefaultServerUrl: () => getDefaultServerUrl(),
    setDefaultServerUrl: (url) => setDefaultServerUrl(url),
    getDisplayBackend: async () => null,
    setDisplayBackend: async () => undefined,
    checkAppExists: (appName) => checkAppExists(appName),
    resolveAppPath: async (appName) => resolveAppPath(appName),
    updater,
    showUpdater: () => showUpdaterDialog(updater, true),
    setBackgroundColor: (color) => setBackgroundColor(color),
    exportDebugLogs: () => exportDebugLogs(),
    recordFatalRendererError: (error) => writeLog("renderer", "fatal renderer error", { ...error }, "error"),
  })
  registerWslIpcHandlers(wslServers)
  void updater.start()
  const updateTimer = setInterval(() => void updater.check(), 10 * 60 * 1000)
  updateTimer.unref()
  app.once("will-quit", () => clearInterval(updateTimer))
  yield* Effect.promise(() => startNetLog()).pipe(
    Effect.catch((error) =>
      Effect.sync(() => {
        logger.warn("failed to start net log", error)
      }),
    ),
  )

  const loadingTask = yield* Effect.gen(function* () {
    ensureLoopbackNoProxy()
    useEnvProxy()

    if (process.platform === "win32") {
      logger.log("spawning primary WSL2 server")
      const sidecar = yield* Effect.promise(() =>
        spawnPrimaryWslSidecar({
          onLine: (line) =>
            writeLog("server", line.stream, { message: line.text }, line.stream === "stderr" ? "warn" : "info"),
        }),
      )
      server = sidecar.listener
      yield* Deferred.succeed(serverReady, {
        url: sidecar.url,
        username: sidecar.username,
        password: sidecar.password,
        runtime: "wsl2",
        distro: sidecar.distro,
        architecture: sidecar.architecture,
        packageVersion: sidecar.packageVersion,
        wslVersion: sidecar.wslVersion,
        tools: sidecar.tools,
      })
      if (WSL_MULTI_SERVER_MANAGEMENT_ENABLED) {
        void wslServers.initialize().catch((error) => logger.error("wsl server initialization failed", error))
      }
    } else {
      if (process.platform === "linux") {
        yield* Effect.promise(() => ensureNativeLinuxWorkerImage())
      }
      const runtimeTools =
        process.platform === "linux"
          ? linuxFirstRuntimePreflight()
          : process.platform === "darwin"
            ? nativeRuntimePreflight()
            : undefined
      if (process.platform === "linux") {
        if (runtimeTools?.["web.browse"]?.available) process.env.ARGOS_BROWSER_WORKER_AVAILABLE = "1"
        else delete process.env.ARGOS_BROWSER_WORKER_AVAILABLE
      }
      const port = yield* Effect.gen(function* () {
        const fromEnv = process.env.ARGOS_PORT ?? process.env.OPENCODE_PORT
        if (fromEnv) {
          const parsed = Number.parseInt(fromEnv, 10)
          if (!Number.isNaN(parsed)) return parsed
        }

        const res = yield* Deferred.make<number, unknown>()
        const portServer = createServer()
        portServer.on("error", (error) => Deferred.failSync(res, () => error))
        portServer.listen(0, "127.0.0.1", () => {
          const address = portServer.address()
          if (typeof address !== "object" || !address) {
            portServer.close()
            Deferred.failSync(res, () => new Error("Failed to get port"))
            return
          }
          const availablePort = address.port
          portServer.close(() => Effect.runSync(Deferred.succeed(res, availablePort)))
        })

        return yield* Deferred.await(res)
      })
      const hostname = "127.0.0.1"
      const url = `http://${hostname}:${port}`
      const password = randomUUID()
      process.env.ARGOS_SERVER_PASSWORD = password
      process.env.OPENCODE_SERVER_PASSWORD = password

      logger.log("spawning local server", { url })
      const { listener, health } = yield* Effect.promise(() =>
        spawnLocalServer(hostname, port, password, {
          userDataPath: app.getPath("userData"),
          onStdout: (message) => writeLog("server", "stdout", { message }),
          onStderr: (message) => writeLog("server", "stderr", { message }, "warn"),
          onExit: (code) => writeLog("utility", "sidecar exited", { code }, "warn"),
        }),
      )
      server = listener
      yield* Deferred.succeed(serverReady, {
        url,
        username: "opencode",
        password,
        runtime: process.platform === "linux" ? "linux" : "macos",
        tools: runtimeTools,
      })

      yield* Effect.promise(() => health.wait).pipe(
        Effect.timeout("30 seconds"),
        Effect.catch((error) =>
          Effect.sync(() => {
            logger.error("sidecar health check failed", error.toString())
          }),
        ),
      )
    }

    logger.log("loading task finished")
  }).pipe(forwardInitializationFailure(serverReady), Effect.forkChild)

  yield* Fiber.await(loadingTask)

  mainWindow = createMainWindow()
  if (mainWindow) {
    createMenu({
      trigger: (id) => {
        const win = BrowserWindow.getFocusedWindow() ?? mainWindow
        if (win) sendMenuCommand(win, id)
      },
      checkForUpdates: () => {
        void showUpdaterDialog(updater, true)
      },
      relaunch: () => {
        relaunch()
      },
    })
  }
})

Effect.runFork(main)
