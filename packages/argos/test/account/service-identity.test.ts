import { expect, test } from "bun:test"
import { Effect, Layer, Option } from "effect"
import { Auth as ProviderAuth } from "@argos/core/auth"
import { Account as ArgosAccount } from "../../src/account/account"

test("provider auth and Argos cloud account resolve to separate services", async () => {
  const providerService = ProviderAuth.Service.of({
    activeAll: () => Effect.succeed(new Map()),
  } as unknown as ProviderAuth.Interface)
  const argosAccountService = ArgosAccount.Service.of({
    active: () => Effect.succeed(Option.none()),
  } as unknown as ArgosAccount.Interface)
  const services = Effect.gen(function* () {
    const providerAuth = yield* ProviderAuth.Service
    const argosAccount = yield* ArgosAccount.Service
    return {
      providerAuthAvailable: typeof providerAuth.activeAll === "function",
      argosAccountAvailable: typeof argosAccount.active === "function",
    }
  })

  const result = await Effect.runPromise(
    Effect.provide(
      services,
      Layer.mergeAll(
        Layer.succeed(ProviderAuth.Service, providerService),
        Layer.succeed(ArgosAccount.Service, argosAccountService),
      ),
    ),
  )

  expect(result).toEqual({ providerAuthAvailable: true, argosAccountAvailable: true })
})
