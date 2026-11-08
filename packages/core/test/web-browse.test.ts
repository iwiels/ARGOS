import { describe, expect, it } from "bun:test"
import { WebBrowseTool } from "@argos/core/tool/web-browse"

describe("web.browse (Playwright Browser Hunting)", () => {
  it("fails closed instead of launching a host browser", async () => {
    await expect(WebBrowseTool.defaultLauncher()).rejects.toThrow("host browser execution is disabled")
  })

  it("expone las acciones navigate, login, check_authz y dom_xss", () => {
    expect(WebBrowseTool).toBeDefined()
    expect(WebBrowseTool.actions).toContain("navigate")
    expect(WebBrowseTool.actions).toContain("login")
    expect(WebBrowseTool.actions).toContain("check_authz")
    expect(WebBrowseTool.actions).toContain("dom_xss")
  })

  it("valida la definición de Tool y Layer de Effect", () => {
    expect(WebBrowseTool.name).toBe("web.browse")
    expect(WebBrowseTool.layer).toBeDefined()
    expect(WebBrowseTool.description).toBeDefined()
  })

  it("valida y decodifica correctamente esquemas de entrada para cada acción", () => {
    const { Schema } = require("effect")

    // navigate
    const nav = Schema.decodeUnknownSync(WebBrowseTool.Input)({
      action: "navigate",
      url: "https://example.com/app",
    })
    expect(nav.action).toBe("navigate")
    expect(nav.url).toBe("https://example.com/app")

    // login
    const login = Schema.decodeUnknownSync(WebBrowseTool.Input)({
      action: "login",
      url: "https://example.com/login",
      authProfileID: "profile_1",
    })
    expect(login.authProfileID).toBe("profile_1")
    expect("credentials" in login).toBe(false)
    expect("storageState" in login).toBe(false)

    // check_authz
    const authz = Schema.decodeUnknownSync(WebBrowseTool.Input)({
      action: "check_authz",
      url: "https://example.com/api",
      authzCompare: {
        roleAAuthProfileID: "role_a",
        roleBAuthProfileID: "role_b",
        endpointUrl: "https://example.com/api/v1/users",
      },
    })
    expect(authz.authzCompare?.endpointUrl).toBe("https://example.com/api/v1/users")

    // dom_xss
    const xss = Schema.decodeUnknownSync(WebBrowseTool.Input)({
      action: "dom_xss",
      url: "https://example.com/search",
      xssParam: "q",
    })
    expect(xss.xssParam).toBe("q")

    // acción inválida debe lanzar error de schema
    expect(() =>
      Schema.decodeUnknownSync(WebBrowseTool.Input)({
        action: "unsupported_action",
        url: "https://example.com",
      }),
    ).toThrow()
  })
})
