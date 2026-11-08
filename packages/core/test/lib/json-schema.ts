/**
 * Validador de JSON Schema (subconjunto) para los tests de export.
 *
 * Cubre exactamente el vocabulario que usan los dos schemas oficiales
 * vendorizados en `packages/core/test/fixtures/schema/`:
 * `$ref`, `type`, `enum`, `const`, `properties`, `required`, `additionalProperties`,
 * `items` (esquema o tupla), `additionalItems`, `minItems`, `maxItems`,
 * `uniqueItems`, `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`,
 * `allOf`, `anyOf` y `oneOf`.
 *
 * `format` se ignora a propósito: en JSON Schema es una anotación y los
 * validadores conformes no rechazan por ella.
 */

export interface SchemaViolation {
  path: string
  keyword: string
  message: string
}

type Schema = Record<string, any>

const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false
    return a.every((item, index) => deepEqual(item, b[index]))
  }
  if (isObject(a) && isObject(b)) {
    const aKeys = Object.keys(a).sort()
    const bKeys = Object.keys(b).sort()
    if (aKeys.length !== bKeys.length) return false
    if (aKeys.some((key, index) => key !== bKeys[index])) return false
    return aKeys.every((key) => deepEqual(a[key], b[key]))
  }
  return false
}

function typeOf(value: unknown): string {
  if (value === null) return "null"
  if (Array.isArray(value)) return "array"
  if (Number.isInteger(value)) return "integer"
  return typeof value
}

function matchesType(value: unknown, expected: string): boolean {
  const actual = typeOf(value)
  if (expected === "number") return actual === "number" || actual === "integer"
  if (expected === "integer") return actual === "integer"
  return actual === expected
}

function resolveRef(root: Schema, ref: string): Schema | undefined {
  if (ref === "#") return root
  if (!ref.startsWith("#/")) return undefined
  let current: any = root
  for (const raw of ref.slice(2).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~")
    if (!current || typeof current !== "object") return undefined
    current = current[key]
  }
  return current && typeof current === "object" ? (current as Schema) : undefined
}

export function validateAgainstSchema(value: unknown, schema: Schema, root: Schema = schema): SchemaViolation[] {
  const violations: SchemaViolation[] = []
  const report = (path: string, keyword: string, message: string) => violations.push({ path, keyword, message })

  const walk = (node: unknown, current: Schema | undefined, path: string) => {
    if (!current) return

    if (typeof current.$ref === "string") {
      const resolved = resolveRef(root, current.$ref)
      if (!resolved) {
        report(path, "$ref", `no se pudo resolver la referencia ${current.$ref}`)
        return
      }
      walk(node, resolved, path)
      return
    }

    if (current.type !== undefined) {
      const expected = Array.isArray(current.type) ? current.type : [current.type]
      if (!expected.some((candidate) => matchesType(node, candidate as string))) {
        report(path, "type", `se esperaba ${expected.join(" | ")} y se recibió ${typeOf(node)}`)
        return
      }
    }

    if (current.enum !== undefined && !current.enum.some((candidate: unknown) => deepEqual(candidate, node))) {
      report(path, "enum", `el valor no pertenece al enum permitido`)
    }

    if (current.const !== undefined && !deepEqual(current.const, node)) {
      report(path, "const", `el valor debe ser ${JSON.stringify(current.const)}`)
    }

    if (typeof node === "string") {
      if (typeof current.minLength === "number" && node.length < current.minLength)
        report(path, "minLength", `la cadena es más corta que ${current.minLength}`)
      if (typeof current.maxLength === "number" && node.length > current.maxLength)
        report(path, "maxLength", `la cadena es más larga que ${current.maxLength}`)
      if (typeof current.pattern === "string" && !new RegExp(current.pattern).test(node))
        report(path, "pattern", `la cadena no cumple ${current.pattern}`)
    }

    if (typeof node === "number") {
      if (typeof current.minimum === "number" && node < current.minimum)
        report(path, "minimum", `el valor es menor que ${current.minimum}`)
      if (typeof current.maximum === "number" && node > current.maximum)
        report(path, "maximum", `el valor es mayor que ${current.maximum}`)
    }

    if (Array.isArray(node)) {
      if (typeof current.minItems === "number" && node.length < current.minItems)
        report(path, "minItems", `faltan elementos (mínimo ${current.minItems})`)
      if (typeof current.maxItems === "number" && node.length > current.maxItems)
        report(path, "maxItems", `sobran elementos (máximo ${current.maxItems})`)
      if (current.uniqueItems === true) {
        for (let index = 0; index < node.length; index++) {
          for (let other = index + 1; other < node.length; other++) {
            if (deepEqual(node[index], node[other])) {
              report(`${path}/${index}`, "uniqueItems", `elemento duplicado`)
            }
          }
        }
      }
      if (Array.isArray(current.items)) {
        node.forEach((item, index) => {
          if (index < current.items.length) {
            walk(item, current.items[index], `${path}/${index}`)
            return
          }
          if (current.additionalItems && typeof current.additionalItems === "object") {
            walk(item, current.additionalItems, `${path}/${index}`)
          }
        })
      } else if (current.items && typeof current.items === "object") {
        node.forEach((item, index) => walk(item, current.items, `${path}/${index}`))
      }
    }

    if (isObject(node)) {
      for (const key of current.required ?? []) {
        if (!(key in node)) report(`${path}/${key}`, "required", `falta la propiedad obligatoria`)
      }
      const properties = current.properties ?? {}
      for (const [key, child] of Object.entries(node)) {
        const childSchema = properties[key]
        if (childSchema && typeof childSchema === "object") {
          walk(child, childSchema as Schema, `${path}/${key}`)
          continue
        }
        if (current.additionalProperties === false) {
          report(`${path}/${key}`, "additionalProperties", `la propiedad ${key} no está permitida`)
          continue
        }
        if (current.additionalProperties && typeof current.additionalProperties === "object") {
          walk(child, current.additionalProperties as Schema, `${path}/${key}`)
        }
      }
    }

    if (Array.isArray(current.allOf)) {
      current.allOf.forEach((sub: Schema) => walk(node, sub, path))
    }
    if (Array.isArray(current.anyOf)) {
      const matches = current.anyOf.some((sub: Schema) => validateAgainstSchema(node, sub, root).length === 0)
      if (!matches) report(path, "anyOf", `ninguna de las alternativas se cumple`)
    }
    if (Array.isArray(current.oneOf)) {
      const matches = current.oneOf.filter((sub: Schema) => validateAgainstSchema(node, sub, root).length === 0).length
      if (matches !== 1) report(path, "oneOf", `se cumple ${matches} alternativas y debe cumplirse exactamente una`)
    }
  }

  walk(value, schema, "#")
  return violations
}
