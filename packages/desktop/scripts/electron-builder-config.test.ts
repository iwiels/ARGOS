import { expect, test } from "bun:test"
import config from "../electron-builder.config"

test("Linux package uses a safe executable name and repository-root runtime resources", () => {
  const channel = process.env.OPENCODE_CHANNEL
  const expectedExecutableName = channel === "prod" ? "argos" : `argos-${channel === "beta" ? "beta" : "dev"}`

  expect(config.linux).toMatchObject({ executableName: expectedExecutableName })

  const resourcePaths = (config.extraResources ?? []) as Array<{ from?: string }>
  expect(resourcePaths.map((resource) => resource.from)).toContain("../../argos-bin/bin/")
  expect(resourcePaths.map((resource) => resource.from)).toContain("../../argos-config/")
})
