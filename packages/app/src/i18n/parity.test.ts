import { describe, expect, test } from "bun:test"
import { dict as en } from "./en"
import { dict as ar } from "./ar"
import { dict as br } from "./br"
import { dict as bs } from "./bs"
import { dict as da } from "./da"
import { dict as de } from "./de"
import { dict as es } from "./es"
import { dict as fr } from "./fr"
import { dict as ja } from "./ja"
import { dict as ko } from "./ko"
import { dict as no } from "./no"
import { dict as pl } from "./pl"
import { dict as ru } from "./ru"
import { dict as uk } from "./uk"
import { dict as th } from "./th"
import { dict as zh } from "./zh"
import { dict as zht } from "./zht"
import { dict as tr } from "./tr"

const locales = [ar, br, bs, da, de, es, fr, ja, ko, no, pl, ru, uk, th, tr, zh, zht]

/**
 * Trinquete de cobertura i18n:
 * - Ningún locale puede tener claves desconocidas (extra).
 * - `es` (idioma principal del producto) exige paridad completa con `en`.
 * - Los demás locales tienen un piso mínimo; súbelo cada vez que se
 *   completen traducciones. La meta final es paridad total en los 18.
 */
const MIN_TRANSLATED_KEYS = 832

describe("i18n parity", () => {
  const enKeys = Object.keys(en)

  test("no locale defines keys outside the English base", () => {
    const enSet = new Set(enKeys)
    for (const locale of locales) {
      const extra = Object.keys(locale).filter((key) => !enSet.has(key))
      expect(extra).toEqual([])
    }
  })

  test("Spanish (primary product language) is at full parity", () => {
    const esKeys = new Set(Object.keys(es))
    const missing = enKeys.filter((key) => !esKeys.has(key))
    expect(missing).toEqual([])
  })

  test("every locale meets the translated-keys floor", () => {
    for (const locale of locales) {
      expect(Object.keys(locale).length, `locale fell below ${MIN_TRANSLATED_KEYS} keys`).toBeGreaterThanOrEqual(
        MIN_TRANSLATED_KEYS,
      )
    }
  })

  test("targeted unseen session keys are translated, not copied from English", () => {
    for (const locale of locales) {
      for (const key of ["command.session.previous.unseen", "command.session.next.unseen"] as const) {
        expect(locale[key]).toBeDefined()
        expect(locale[key]).not.toBe(en[key])
      }
    }
  })
})
