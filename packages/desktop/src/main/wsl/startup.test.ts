import { expect, test } from "bun:test"
import {
  argosWslRootfsArtifact,
  argosWslRootfsSource,
  buildWslImportArgs,
  parseDebianRootfsOciManifest,
  validateDebianRootfsOciConfig,
  selectArgosRuntimeDistro,
  selectPrimaryWslDistro,
  wslArchitectureToGoArch,
} from "./startup"

test("prefers a saved WSL2 distro, then the default, then the first WSL2 distro", () => {
  const distros = [
    { name: "Ubuntu-20.04", version: 1, isDefault: true },
    { name: "Debian", version: 2, isDefault: false },
    { name: "Ubuntu-24.04", version: 2, isDefault: false },
  ]
  expect(selectPrimaryWslDistro(distros, "Ubuntu-24.04")?.name).toBe("Ubuntu-24.04")
  expect(selectPrimaryWslDistro(distros)?.name).toBe("Debian")
  expect(selectPrimaryWslDistro(distros, "Ubuntu-20.04")?.name).toBe("Debian")
})

test("requires a WSL2 distro for the Linux-first backend", () => {
  expect(selectPrimaryWslDistro([{ name: "Ubuntu-20.04", version: 1, isDefault: true }])).toBeNull()
})

test("selects only Argos's managed WSL distro and never adopts the user's default distro", () => {
  const distros = [
    { name: "Ubuntu", version: 2, isDefault: true },
    { name: "ArgosRuntime", version: 2, isDefault: false },
  ]
  expect(selectArgosRuntimeDistro(distros)?.name).toBe("ArgosRuntime")
  expect(selectArgosRuntimeDistro([distros[0]])).toBeNull()
})

test("pins the minimal Debian WSL rootfs independently for amd64 and arm64", () => {
  const amd64 = argosWslRootfsArtifact("amd64")
  expect(amd64.architecture).toBe("amd64")
  expect(amd64.imageManifestSha256).toBe("1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d")
  expect(amd64.repository).toBe("https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts")
  const arm64 = argosWslRootfsArtifact("arm64")
  expect(arm64.architecture).toBe("arm64")
  expect(arm64.imageManifestSha256).toBe("1470991b497d26788dc4d6f438bf5690c6ba0d499235d237e55f4b43caea7a75")
  expect(arm64.repository).toBe("https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts")
})

test("downloads Debian Slim canonical OCI files instead of Git symlink blobs", () => {
  expect(argosWslRootfsSource("amd64")).toEqual({
    manifestUrl:
      "https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/69faaf492e77aff83e4c7fc401017c9d25ecde24/trixie/slim/oci/blobs/image-manifest.json",
    configUrl:
      "https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/69faaf492e77aff83e4c7fc401017c9d25ecde24/trixie/slim/oci/blobs/image-config.json",
    rootfsUrl:
      "https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/69faaf492e77aff83e4c7fc401017c9d25ecde24/trixie/slim/oci/blobs/rootfs.tar.gz",
  })
  expect(argosWslRootfsSource("arm64").manifestUrl).toBe(
    "https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/e36653f9967231373aeba7cff2102fd004ac4f4a/trixie/slim/oci/blobs/image-manifest.json",
  )
})

test("accepts a single gzip rootfs layer from the pinned Debian OCI image manifest", () => {
  expect(
    parseDebianRootfsOciManifest({
      schemaVersion: 2,
      config: { digest: `sha256:${"a".repeat(64)}` },
      layers: [{ mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: `sha256:${"b".repeat(64)}` }],
    }),
  ).toEqual({ configSha256: "a".repeat(64), rootfsSha256: "b".repeat(64) })
  expect(() =>
    parseDebianRootfsOciManifest({ schemaVersion: 2, config: {}, layers: [{ mediaType: "application/zstd" }] }),
  ).toThrow("Debian rootfs manifest")
})

test("verifies that the Debian OCI config is for the requested Linux architecture", () => {
  expect(validateDebianRootfsOciConfig({ architecture: "amd64", os: "linux" }, "amd64")).toBe(true)
  expect(() => validateDebianRootfsOciConfig({ architecture: "arm64", os: "linux" }, "amd64")).toThrow(
    "architecture",
  )
})

test("imports the pinned rootfs only as a new WSL2 distro", () => {
  expect(buildWslImportArgs("C:\\Users\\victor\\AppData\\Local\\Argos\\wsl", "C:\\Temp\\rootfs.tar.gz")).toEqual([
    "--import",
    "ArgosRuntime",
    "C:\\Users\\victor\\AppData\\Local\\Argos\\wsl",
    "C:\\Temp\\rootfs.tar.gz",
    "--version",
    "2",
  ])
})

test("normalizes supported Linux architectures and rejects unsupported ones", () => {
  expect(wslArchitectureToGoArch("x86_64")).toBe("amd64")
  expect(wslArchitectureToGoArch("x64")).toBe("amd64")
  expect(wslArchitectureToGoArch("aarch64")).toBe("arm64")
  expect(() => wslArchitectureToGoArch("i686")).toThrow("unsupported Linux architecture")
})
