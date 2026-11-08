import type { WslDistroProbe, WslOpencodeCheck, WslServerItem } from "../../preload/types"

export function wslServerIdToRestart(servers: WslServerItem[], distro: string) {
  return servers.find((item) => item.config.distro === distro)?.config.id
}

export function clearWslDistroState(
  distroProbes: Record<string, WslDistroProbe>,
  opencodeChecks: Record<string, WslOpencodeCheck>,
  distro: string,
) {
  const nextDistroProbes = { ...distroProbes }
  const nextOpencodeChecks = { ...opencodeChecks }
  delete nextDistroProbes[distro]
  delete nextOpencodeChecks[distro]
  return { distroProbes: nextDistroProbes, opencodeChecks: nextOpencodeChecks }
}

export function wslTerminalArgs(distro?: string | null) {
  return ["/c", "start", "", "wsl", ...(distro ? ["-d", distro] : [])]
}

export function requireWslIpcString(name: string, value: unknown) {
  if (typeof value === "string" && value.length > 0) return value
  throw new Error(`Invalid ${name}`)
}

// Distro names flow into `cmd.exe /c start ... wsl -d <name>`; cmd
// metacharacters (& | ^ % ! " < >) in a renderer-supplied name would break
// out of argument quoting. WSL distro names are alphanumeric plus dot,
// dash, underscore (and may contain spaces), so anything else is rejected.
const WSL_DISTRO_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/

export function requireWslDistroName(name: string, value: unknown) {
  const distro = requireWslIpcString(name, value)
  if (!WSL_DISTRO_NAME.test(distro)) {
    throw new Error(`Invalid ${name}`)
  }
  return distro
}




