import { expect, test } from "bun:test"
import { goBuildTargetsFor } from "./go-build-targets"

test("builds Linux web and runner assets for Windows amd64 packages", () => {
  expect(goBuildTargetsFor("win32", "x64")).toEqual([
    { goos: "windows", goarch: "amd64", commands: ["orquestador", "lan", "web", "es"] },
    { goos: "linux", goarch: "amd64", commands: ["orquestador", "web", "argos-runner"] },
  ])
})

test("builds the Linux web and runner profile for native arm64", () => {
  expect(goBuildTargetsFor("linux", "arm64")).toEqual([
    { goos: "linux", goarch: "arm64", commands: ["orquestador", "web", "argos-runner"] },
  ])
})

test("preserves the macOS binary set", () => {
  expect(goBuildTargetsFor("darwin", "x64")).toEqual([
    { goos: "darwin", goarch: "amd64", commands: ["orquestador", "lan", "web", "es"] },
  ])
})

test("rejects architectures the Go runtime package does not build", () => {
  expect(() => goBuildTargetsFor("linux", "ia32")).toThrow("Unsupported Go build architecture")
})

