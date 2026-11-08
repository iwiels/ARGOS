export type GoBuildTarget = {
  goos: "windows" | "linux" | "darwin"
  goarch: "amd64" | "arm64"
  commands: string[]
}

const completeCommands = ["orquestador", "lan", "web", "es"]
const linuxAuditCommands = ["orquestador", "web", "argos-runner"]

function normalizeGoArch(architecture: string): GoBuildTarget["goarch"] {
  if (architecture === "x64") return "amd64"
  if (architecture === "arm64") return "arm64"
  throw new Error(`Unsupported Go build architecture: ${architecture}`)
}

export function goBuildTargetsFor(platform: string, architecture: string): GoBuildTarget[] {
  const goarch = normalizeGoArch(architecture)
  if (platform === "win32") {
    return [
      { goos: "windows", goarch, commands: [...completeCommands] },
      { goos: "linux", goarch, commands: [...linuxAuditCommands] },
    ]
  }
  if (platform === "linux") {
    return [{ goos: "linux", goarch, commands: [...linuxAuditCommands] }]
  }
  if (platform === "darwin") {
    return [{ goos: "darwin", goarch, commands: [...completeCommands] }]
  }
  throw new Error(`Unsupported Go build platform: ${platform}`)
}
