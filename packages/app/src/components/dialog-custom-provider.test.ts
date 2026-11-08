import { describe, expect, test } from "bun:test"
import * as fc from "fast-check"
import { validateCustomProvider } from "./dialog-custom-provider-form"

const t = (key: string) => key

describe("validateCustomProvider", () => {
  test("builds trimmed config payload", () => {
    const result = validateCustomProvider({
      form: {
        providerID: "custom-provider",
        name: " Custom Provider ",
        baseURL: "https://api.example.com ",
        apiKey: " {env: CUSTOM_PROVIDER_KEY} ",
        models: [{ row: "m0", id: " model-a ", name: " Model A ", err: {} }],
        headers: [
          { row: "h0", key: " X-Test ", value: " enabled ", err: {} },
          { row: "h1", key: "", value: "", err: {} },
        ],
        err: {},
      },
      t,
      disabledProviders: [],
      existingProviderIDs: new Set(),
    })

    expect(result.result).toEqual({
      providerID: "custom-provider",
      name: "Custom Provider",
      key: undefined,
      config: {
        npm: "@ai-sdk/openai-compatible",
        name: "Custom Provider",
        env: ["CUSTOM_PROVIDER_KEY"],
        options: {
          baseURL: "https://api.example.com",
          headers: {
            "X-Test": "enabled",
          },
        },
        models: {
          "model-a": { name: "Model A" },
        },
      },
    })
  })

  test("flags duplicate rows and allows reconnecting disabled providers", () => {
    const result = validateCustomProvider({
      form: {
        providerID: "custom-provider",
        name: "Provider",
        baseURL: "https://api.example.com",
        apiKey: "secret",
        models: [
          { row: "m0", id: "model-a", name: "Model A", err: {} },
          { row: "m1", id: "model-a", name: "Model A 2", err: {} },
        ],
        headers: [
          { row: "h0", key: "Authorization", value: "one", err: {} },
          { row: "h1", key: "authorization", value: "two", err: {} },
        ],
        err: {},
      },
      t,
      disabledProviders: ["custom-provider"],
      existingProviderIDs: new Set(["custom-provider"]),
    })

    expect(result.result).toBeUndefined()
    expect(result.err.providerID).toBeUndefined()
    expect(result.models[1]).toEqual({
      id: "provider.custom.error.duplicate",
      name: undefined,
    })
    expect(result.headers[1]).toEqual({
      key: "provider.custom.error.duplicate",
      value: undefined,
    })
  })
})

describe("validateCustomProvider property tests", () => {
  const validForm = {
    providerID: "my-provider",
    name: "My Provider",
    baseURL: "https://api.example.com",
    apiKey: "test-key-123",
    models: [{ row: "m0", id: "gpt-4", name: "GPT-4", err: {} }],
    headers: [{ row: "h0", key: "Authorization", value: "Bearer token", err: {} }],
    err: {},
  }

  test("invariance: providerID must match ^[a-z0-9][a-z0-9-_]*$", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 30 }),
        (providerID) => {
          const result = validateCustomProvider({
            form: { ...validForm, providerID },
            t,
            disabledProviders: [],
            existingProviderIDs: new Set(),
          })
          if (/^[a-z0-9][a-z0-9-_]*$/.test(providerID.trim())) {
            expect(result.err.providerID).toBeUndefined()
          } else {
            expect(result.err.providerID).toBeTruthy()
          }
        },
      ),
    )
  })

  test("invariance: empty or whitespace-only fields produce errors", () => {
    expect(
      validateCustomProvider({
        form: { ...validForm, providerID: "  ", name: "  ", baseURL: "  " },
        t,
        disabledProviders: [],
        existingProviderIDs: new Set(),
      }).err,
    ).toMatchObject({
      providerID: expect.any(String),
      name: expect.any(String),
      baseURL: expect.any(String),
    })
  })

  test("invariance: valid provider always produces a result with config", () => {
    const result = validateCustomProvider({
      form: validForm,
      t,
      disabledProviders: [],
      existingProviderIDs: new Set(),
    })
    expect(result.result).toBeDefined()
    expect(result.result?.config).toBeDefined()
    expect(result.result?.config.options.baseURL).toBe("https://api.example.com")
  })
})


