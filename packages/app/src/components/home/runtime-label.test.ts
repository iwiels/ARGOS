import { expect, test } from "bun:test"
import { homeRuntimeMessage } from "./runtime-label"

test("reports the runtime that actually hosts the primary Windows sidecar", () => {
  expect(
    homeRuntimeMessage(
      {
        type: "sidecar",
        variant: "base",
        runtime: { kind: "wsl2", distro: "Ubuntu-24.04" },
        http: { url: "http://127.0.0.1:4321" },
      },
      { platform: "desktop", os: "windows" },
      true,
    ),
  ).toEqual({ key: "home.runtime.wsl", params: { distro: "Ubuntu-24.04" } })
})

test("keeps a native Windows sidecar labeled as Windows", () => {
  expect(
    homeRuntimeMessage(
      { type: "sidecar", variant: "base", http: { url: "http://127.0.0.1:4321" } },
      { platform: "desktop", os: "windows" },
      true,
    ),
  ).toEqual({ key: "home.runtime.windows" })
})
