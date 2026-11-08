import type { WslServersState } from "@argos/app/wsl/types"
import type { ServerConnection } from "@argos/app"
import type { ServerReadyData } from "../../preload/types"

export function primaryServerConnection(data: ServerReadyData): ServerConnection.Any {
  const wslRuntime = data.runtime === "wsl2" && data.distro ? { kind: "wsl2" as const, distro: data.distro } : undefined
  return {
    displayName:
      data.runtime === "wsl2"
        ? `WSL 2 · ${data.distro}`
        : data.runtime === "linux"
          ? "Linux Server"
          : "Local Server",
    type: "sidecar",
    variant: "base",
    ...(wslRuntime ? { runtime: wslRuntime } : {}),
    http: {
      url: data.url,
      username: data.username ?? undefined,
      password: data.password ?? undefined,
    },
  }
}

export function readyWslConnections(state?: WslServersState) {
  return (state?.servers ?? []).flatMap((item) => {
    if (item.runtime.kind !== "ready") return []
    return [
      {
        displayName: item.config.distro,
        label: "WSL",
        type: "sidecar" as const,
        variant: "wsl" as const,
        distro: item.config.distro,
        http: {
          url: item.runtime.url,
          username: item.runtime.username ?? undefined,
          password: item.runtime.password ?? undefined,
        },
      },
    ]
  })
}

export function availableStartupServer(defaultServer: string | null | undefined, state?: WslServersState) {
  const key = defaultServer ?? "sidecar"
  if (!key.startsWith("wsl:")) return key
  if (state?.servers.some((item) => item.config.id === key && item.runtime.kind === "ready")) return key
  return "sidecar"
}




