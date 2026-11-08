import type { ServerConnection } from "@/context/server"

type RuntimeMessage = { key: string; params?: Record<string, string | number | boolean> }

export function homeRuntimeMessage(
  connection: ServerConnection.Any | undefined,
  platform: { platform: string; os?: string },
  local: boolean,
): RuntimeMessage {
  if (!connection) return { key: "home.runtime.unknown" }
  if (connection.type === "sidecar") {
    const distro =
      connection.runtime?.kind === "wsl2"
        ? connection.runtime.distro
        : connection.variant === "wsl"
          ? connection.distro
          : undefined
    if (distro) return { key: "home.runtime.wsl", params: { distro } }
    if (platform.platform === "desktop") {
      if (platform.os === "windows") return { key: "home.runtime.windows" }
      if (platform.os === "linux") return { key: "home.runtime.linux" }
      if (platform.os === "macos") return { key: "home.runtime.macos" }
    }
    return { key: "home.runtime.localHost" }
  }
  if (connection.type === "ssh") return { key: "home.runtime.ssh", params: { host: connection.host } }
  return { key: local ? "home.runtime.localServer" : "home.runtime.remoteServer" }
}
