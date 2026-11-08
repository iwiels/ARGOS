import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { Service as OpenCodeService } from "../src/public/opencode"
import { Argos } from "../src/public"
import { Database } from "@argos/core/database/database"
import { testEffect } from "./lib/effect"

const it = testEffect(Argos.layerWithStorage(Database.layerFromPath(":memory:")))

describe("public opencode backward compatibility shim", () => {
  it.effect("allows importing Service from public/opencode directly", () =>
    Effect.gen(function* () {
      const opencode = yield* OpenCodeService
      expect(Object.keys(opencode).sort()).toEqual(["sessions", "tools"])
    }),
  )
})
