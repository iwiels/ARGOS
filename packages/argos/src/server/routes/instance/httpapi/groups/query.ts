import { NonNegativeInt } from "@argos/core/schema"
import { Schema, SchemaGetter } from "effect"

export const QueryBoolean = Schema.Literals(["true", "false"]).pipe(
  Schema.decodeTo(Schema.Boolean, {
    decode: SchemaGetter.transform((value) => value === "true"),
    encode: SchemaGetter.transform((value) => (value ? "true" : "false")),
  }),
)

export const QueryBooleanOpenApi = {
  anyOf: [{ type: "boolean" }, { type: "string", enum: ["true", "false"] }],
}

export const QueryNonNegativeInt = Schema.Union([
  NonNegativeInt,
  Schema.NumberFromString.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0)),
])
