import { describe, expect, test } from "bun:test"
import { loadReleaseHighlights } from "./highlights"

describe("release highlights", () => {
  test("reads Argos release notes between the installed and previous versions", () => {
    const releases = [
      { tag_name: "v0.1.0", name: "Argos 0.1.0", body: "Fixes in the audit history." },
      { tag_name: "v0.0.2", name: "Argos 0.0.2", body: "Updates to provider settings." },
      { tag_name: "v0.0.1", name: "Argos 0.0.1", body: "Older release." },
    ]

    expect(loadReleaseHighlights(releases, "0.1.0", "0.0.2")).toEqual([
      { title: "Argos 0.1.0", description: "Fixes in the audit history." },
    ])
  })

  test("ignores draft, prerelease, and empty releases", () => {
    const releases = [
      { tag_name: "v0.1.1-rc.1", name: "Candidate", body: "Pre-release notes.", prerelease: true },
      { tag_name: "v0.1.0", name: "Draft", body: "Draft notes.", draft: true },
      { tag_name: "v0.0.2", name: "Empty", body: "   " },
    ]

    expect(loadReleaseHighlights(releases, "0.1.1", "0.1.0")).toEqual([])
  })
})
