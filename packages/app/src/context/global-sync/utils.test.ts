import { describe, expect, test } from "bun:test"
import * as fc from "fast-check"
import type { Agent } from "@argos/sdk/client"
import { directoryKey, normalizeAgentList, normalizeProviderList, sanitizeProject } from "./utils"

const agent = (name = "build") =>
  ({
    name,
    mode: "primary",
    permission: {},
    options: {},
  }) as Agent

describe("normalizeAgentList", () => {
  test("keeps array payloads", () => {
    expect(normalizeAgentList([agent("build"), agent("docs")])).toEqual([agent("build"), agent("docs")])
  })

  test("wraps a single agent payload", () => {
    expect(normalizeAgentList(agent("docs"))).toEqual([agent("docs")])
  })

  test("extracts agents from keyed objects", () => {
    expect(
      normalizeAgentList({
        build: agent("build"),
        docs: agent("docs"),
      }),
    ).toEqual([agent("build"), agent("docs")])
  })

  test("drops invalid payloads", () => {
    expect(normalizeAgentList({ name: "AbortError" })).toEqual([])
    expect(normalizeAgentList([{ name: "build" }, agent("docs")])).toEqual([agent("docs")])
  })
})

describe("directoryKey", () => {
  test("normalizes slashes", () => {
    expect(String(directoryKey("C:\\Repos\\sst\\opencode"))).toBe("C:/Repos/sst/opencode")
    expect(String(directoryKey("C:/Repos/sst/opencode"))).toBe("C:/Repos/sst/opencode")
  })

  test("preserves backslashes in posix paths", () => {
    expect(String(directoryKey("/tmp/foo\\bar"))).toBe("/tmp/foo\\bar")
  })

  test("trims trailing slashes without breaking roots", () => {
    expect(String(directoryKey("C:/Repos/sst/opencode/"))).toBe("C:/Repos/sst/opencode")
    expect(String(directoryKey("C:/"))).toBe("C:/")
    expect(String(directoryKey("/"))).toBe("/")
  })
})

describe("normalizeProviderList property tests", () => {
  test("idempotence: applying twice is same as once", () => {
    fc.assert(
      fc.property(
        fc.record({
          all: fc.array(
            fc.record({
              id: fc.string(),
              name: fc.string(),
              models: fc.dictionary(fc.string(), fc.record({ status: fc.constantFrom("active", "deprecated") })),
            }),
          ),
          connected: fc.array(fc.string()),
          default: fc.dictionary(fc.string(), fc.string()),
        }),
        (input) => {
          const result = normalizeProviderList({
            all: input.all as any,
            connected: input.connected,
            default: input.default,
          })
          const result2 = normalizeProviderList({
            all: [...result.all.values()] as any,
            connected: result.connected,
            default: result.default,
          })
          expect(result2.all.size).toBe(result.all.size)
          expect(result2.connected).toEqual(result.connected)
        },
      ),
    )
  })

  test("filters out deprecated models", () => {
    const input = {
      all: [
        {
          id: "provider1",
          name: "Provider 1",
          models: { "model-a": { status: "active" as const }, "model-b": { status: "deprecated" as const } },
        },
      ],
      connected: [],
      default: {},
    }
    const result = normalizeProviderList(input as any)
    const provider = result.all.get("provider1")
    expect(provider?.models).not.toHaveProperty("model-b")
    expect(provider?.models).toHaveProperty("model-a")
  })
})

describe("sanitizeProject", () => {
  const baseProject = { id: "test-id", worktree: "/repo", sandboxes: [] as string[], time: { created: 0, updated: 0 } }

  test("removes icon url and override but keeps id and worktree", () => {
    const project = {
      ...baseProject,
      icon: { url: "http://example.com/icon.png", override: "custom" },
    }
    const result = sanitizeProject(project)
    expect(result.icon?.url).toBeUndefined()
    expect(result.icon?.override).toBeUndefined()
    expect(result.id).toBe("test-id")
    expect(result.worktree).toBe("/repo")
  })

  test("preserves project without icon", () => {
    expect(sanitizeProject(baseProject)).toEqual(baseProject)
  })
})
