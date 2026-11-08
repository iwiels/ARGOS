import type { DesktopMenuAction } from "@argos/app/desktop-menu"
import type { WslServersPlatform, WslToolAvailability } from "@argos/app/wsl/types"
import type { UpdaterState } from "@argos/app/updater"
export type {
  WslDistroProbe,
  WslInstalledDistro,
  WslJob,
  WslOnlineDistro,
  WslOpencodeCheck,
  WslRuntimeCheck,
  WslServerConfig,
  WslServerItem,
  WslServerRuntime,
  WslServersEvent,
  WslServersState,
} from "@argos/app/wsl/types"

export type ServerReadyData = {
  url: string
  username: string | null
  password: string | null
  runtime: "wsl2" | "linux" | "macos"
  distro?: string
  architecture?: "amd64" | "arm64"
  packageVersion?: string
  wslVersion?: string | null
  tools?: Record<string, WslToolAvailability>
}

export type WslServersAPI = WslServersPlatform
export type UpdaterAPI = {
  subscribe: (cb: (state: UpdaterState) => void) => Promise<() => void>
  check: () => Promise<UpdaterState>
  install: () => Promise<void>
}

export type LinuxDisplayBackend = "wayland" | "auto"
export type AuthProfileMetadata = { id: string; name: string; username: string; hasBrowserSession: boolean }
export type AuthProfileInput = {
  sessionID: string
  name: string
  username: string
  password: string
  userSelector?: string
  passwordSelector?: string
  submitSelector?: string
  successSelector?: string
}
export type TitlebarTheme = {
  mode: "light" | "dark"
}
export type FatalRendererError = {
  error: string
  url: string
  version?: string
  platform: string
  os?: string
}

export type LocalSubnet = {
  cidr: string
  address: string
  interfaceName: string
}

export type ElectronAPI = {
  killSidecar: () => Promise<void>
  awaitInitialization: () => Promise<ServerReadyData>
  refreshRuntimeTools: () => Promise<Record<string, WslToolAvailability> | null>
  wslServers: WslServersAPI
  authProfiles: {
    list: (sessionID: string) => Promise<AuthProfileMetadata[]>
    save: (input: AuthProfileInput) => Promise<AuthProfileMetadata>
    delete: (sessionID: string, id: string) => Promise<void>
  }
  updater: UpdaterAPI
  consumeInitialDeepLinks: () => Promise<string[]>
  getDefaultServerUrl: () => Promise<string | null>
  setDefaultServerUrl: (url: string | null) => Promise<void>
  getDisplayBackend: () => Promise<LinuxDisplayBackend | null>
  setDisplayBackend: (backend: LinuxDisplayBackend | null) => Promise<void>
  checkAppExists: (appName: string) => Promise<boolean>
  resolveAppPath: (appName: string) => Promise<string | null>
  storeGet: (name: string, key: string) => Promise<string | null>
  storeSet: (name: string, key: string, value: string) => Promise<void>
  storeDelete: (name: string, key: string) => Promise<void>
  storeClear: (name: string) => Promise<void>
  storeKeys: (name: string) => Promise<string[]>
  storeLength: (name: string) => Promise<number>

  getWindowCount: () => Promise<number>
  onMenuCommand: (cb: (id: string) => void) => () => void
  onDeepLink: (cb: (urls: string[]) => void) => () => void

  openDirectoryPicker: (opts?: {
    multiple?: boolean
    title?: string
    defaultPath?: string
  }) => Promise<string | string[] | null>
  openFilePicker: (opts?: {
    multiple?: boolean
    title?: string
    defaultPath?: string
    extensions?: string[]
  }) => Promise<{ token: string; files: { path: string; name: string; size: number }[] } | null>
  readPickedFile: (token: string, path: string) => Promise<ArrayBuffer>
  releasePickedFiles: (token: string) => Promise<void>
  saveFilePicker: (opts?: { title?: string; defaultPath?: string }) => Promise<string | null>
  exportReportPdf: (payload: { filename: string; contentBase64: string }) => Promise<{ path: string } | null>
  exportReportFile: (payload: {
    filename: string
    contentBase64: string
    label?: string
    extensions?: string[]
  }) => Promise<{ path: string } | null>
  openLink: (url: string) => void
  openPath: (path: string, app?: string) => Promise<void>
  readClipboardImage: () => Promise<{ buffer: ArrayBuffer; width: number; height: number } | null>
  showNotification: (title: string, body?: string) => void
  getWindowFocused: () => Promise<boolean>
  setWindowFocus: () => Promise<void>
  showWindow: () => Promise<void>
  relaunch: () => void
  getZoomFactor: () => Promise<number>
  setZoomFactor: (factor: number) => Promise<void>
  getPinchZoomEnabled: () => Promise<boolean>
  setPinchZoomEnabled: (enabled: boolean) => Promise<void>
  onPinchZoomEnabledChanged: (cb: (enabled: boolean) => void) => () => void
  onZoomFactorChanged: (cb: (factor: number) => void) => () => void
  setTitlebar: (theme: TitlebarTheme) => Promise<void>
  runDesktopMenuAction: (action: DesktopMenuAction) => Promise<void>
  setBackgroundColor: (color: string) => Promise<void>
  exportDebugLogs: () => Promise<string>
  recordFatalRendererError: (error: FatalRendererError) => Promise<void>
}
