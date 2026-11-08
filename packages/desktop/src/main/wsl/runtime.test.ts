import { expect, test } from "bun:test"
import { buildManagedDistroCheckArgs, buildWslCommandAvailabilityScript, wslArgs } from "./runtime"

test("runs WSL commands with exec semantics so shell arguments are preserved", () => {
  expect(wslArgs(["bash", "-lc", "printf %s \"$HOME\""], "ArgosRuntime", "argos")).toEqual([
    "-d",
    "ArgosRuntime",
    "--user",
    "argos",
    "--exec",
    "bash",
    "-lc",
    'printf %s "$HOME"',
  ])
})

test("checks the in-distro Argos marker as root before adopting an existing distro", () => {
  expect(buildManagedDistroCheckArgs()).toEqual([
    "-d",
    "ArgosRuntime",
    "--user",
    "root",
    "--exec",
    "/bin/sh",
    "-lc",
    "test -f /var/lib/argos/managed-runtime-ready",
  ])
})

test("builds distro tool availability checks as a single shell loop", () => {
  expect(buildWslCommandAvailabilityScript()).toEqual([
    "for tool in bash curl tar sha256sum wslpath xz grep cut date; do",
    '  if command -v "$tool" >/dev/null 2>&1; then printf "%s=yes\\n" "$tool"; else printf "%s=no\\n" "$tool"; fi',
    "done",
  ])
})
