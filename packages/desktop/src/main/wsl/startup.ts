export function wslServerIdsToStartOnInitialize(servers: { id: string }[]) {
  return servers.map((server) => server.id)
}

export function expectOpencodeVersion(installed: string | null, expected: string, distro = "Debian") {
  if (installed === expected) return
  throw new Error(
    `Argos update finished but ${distro} still reports ${installed ?? "no version"}; expected ${expected}`,
  )
}

export const pendingRestartAfterWslInstall = (runtime: { available: boolean }) => !runtime.available

export const ARGOS_WSL_DISTRO_NAME = "ArgosRuntime"

/** Internal marker written by the Argos bootstrap inside its private distro. */
export const ARGOS_WSL_READY_MARKER = "/var/lib/argos/managed-runtime-ready"

const ARGOS_WSL_ROOTFS = {
  amd64: {
    architecture: "amd64",
    repository: "https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts",
    commit: "69faaf492e77aff83e4c7fc401017c9d25ecde24",
    imageManifestSha256: "1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d",
  },
  arm64: {
    architecture: "arm64",
    repository: "https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts",
    commit: "e36653f9967231373aeba7cff2102fd004ac4f4a",
    imageManifestSha256: "1470991b497d26788dc4d6f438bf5690c6ba0d499235d237e55f4b43caea7a75",
  },
} as const

export function argosWslRootfsArtifact(architecture: "amd64" | "arm64") {
  return ARGOS_WSL_ROOTFS[architecture]
}

export function argosWslRootfsSource(architecture: "amd64" | "arm64") {
  const artifact = argosWslRootfsArtifact(architecture)
  const prefix = `${artifact.repository}/${artifact.commit}/trixie/slim/oci/blobs`
  return {
    manifestUrl: `${prefix}/image-manifest.json`,
    configUrl: `${prefix}/image-config.json`,
    rootfsUrl: `${prefix}/rootfs.tar.gz`,
  }
}

export function parseDebianRootfsOciManifest(value: unknown) {
  if (!value || typeof value !== "object") throw new Error("Debian rootfs manifest is invalid")
  const manifest = value as {
    schemaVersion?: unknown
    config?: { digest?: unknown }
    layers?: { mediaType?: unknown; digest?: unknown }[]
  }
  const config = manifest.config?.digest
  const layer = manifest.layers?.[0]
  if (
    manifest.schemaVersion !== 2 ||
    manifest.layers?.length !== 1 ||
    typeof config !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(config) ||
    layer?.mediaType !== "application/vnd.oci.image.layer.v1.tar+gzip" ||
    typeof layer.digest !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(layer.digest)
  ) {
    throw new Error("Debian rootfs manifest must contain one gzip layer and a SHA-256 config digest")
  }
  return { configSha256: config.slice("sha256:".length), rootfsSha256: layer.digest.slice("sha256:".length) }
}

export function validateDebianRootfsOciConfig(value: unknown, architecture: "amd64" | "arm64") {
  if (!value || typeof value !== "object") throw new Error("Debian rootfs image config is invalid")
  const config = value as { architecture?: unknown; os?: unknown }
  if (config.architecture !== architecture || config.os !== "linux") {
    throw new Error(`Debian rootfs image architecture does not match linux/${architecture}`)
  }
  return true
}

export function buildWslImportArgs(installDirectory: string, rootfsArchive: string) {
  return ["--import", ARGOS_WSL_DISTRO_NAME, installDirectory, rootfsArchive, "--version", "2"]
}

export async function pollWslHealth(check: () => Promise<boolean>, signal: AbortSignal, interval = 100) {
  while (!signal.aborted) {
    if (await check()) return
    await abortableDelay(interval, signal)
  }
}

function abortableDelay(duration: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    const done = () => {
      clearTimeout(timeout)
      signal.removeEventListener("abort", done)
      resolve()
    }
    const timeout = setTimeout(done, duration)
    signal.addEventListener("abort", done, { once: true })
  })
}

export function selectPrimaryWslDistro(
  installed: { name: string; version: number | null; isDefault: boolean }[],
  preferred?: string | null,
) {
  const available = installed.filter((distro) => distro.version === 2)
  return (
    available.find((distro) => distro.name === preferred) ??
    available.find((distro) => distro.isDefault) ??
    available[0] ??
    null
  )
}

export function selectArgosRuntimeDistro(installed: { name: string; version: number | null }[]) {
  return installed.find((distro) => distro.name === ARGOS_WSL_DISTRO_NAME && distro.version === 2) ?? null
}

export function wslArchitectureToGoArch(architecture: string): "amd64" | "arm64" {
  if (architecture === "x86_64" || architecture === "amd64" || architecture === "x64") return "amd64"
  if (architecture === "aarch64" || architecture === "arm64") return "arm64"
  throw new Error(`unsupported Linux architecture: ${architecture}; supported architectures are amd64 and arm64`)
}
