import path from "path"
import fs from "fs/promises"
import { Effect } from "effect"
import { Global } from "../global"
import bundledNist from "./bundled/nist_csf_v2.json"
import bundledIso from "./bundled/iso27001_crosswalk.json"
import bundledChecksNist from "./bundled/checks_nist.json"
import bundledChecksIso from "./bundled/checks_iso.json"
import bundledSoc2 from "./bundled/soc2.json"
import bundledNis2 from "./bundled/nis2.json"
import bundledDora from "./bundled/dora.json"
import bundledPciDss from "./bundled/pci_dss_v4.json"

const COMPLIANCE_DIR = "compliance"

const BUNDLED_CATALOGS: Record<string, Record<string, unknown>> = {
  nist_csf_v2: bundledNist as unknown as Record<string, unknown>,
  iso27001_crosswalk: bundledIso as unknown as Record<string, unknown>,
  checks_nist: bundledChecksNist as unknown as Record<string, unknown>,
  checks_iso: bundledChecksIso as unknown as Record<string, unknown>,
  // Catálogos derivados del crosswalk ISO 27001:2022 (generados por
  // `scripts/gen-compliance-catalogs.ts`).
  soc2: bundledSoc2 as unknown as Record<string, unknown>,
  nis2: bundledNis2 as unknown as Record<string, unknown>,
  dora: bundledDora as unknown as Record<string, unknown>,
  // PCI DSS: catálogo propio (PCI DSS v4.0.1), generado por el mismo script.
  pci_dss_v4: bundledPciDss as unknown as Record<string, unknown>,
}

/** Retorna la ruta del directorio de cache de compliance. */
function getCacheDir(): string {
  return path.join(Global.Path.data, COMPLIANCE_DIR)
}

/** Retorna la ruta del archivo cacheado para una clave. */
function getCachePath(key: string): string {
  // Sanitizar la clave para usarla como nombre de archivo
  const safeKey = key.replace(/[^a-zA-Z0-9_-]/g, "_")
  return path.join(getCacheDir(), `${safeKey}.json`)
}

/** Lee un catálogo desde la cache local o el snapshot bundled. */
export const readCached = (key: string): Effect.Effect<Record<string, unknown> | undefined, never> =>
  Effect.tryPromise(async () => {
    const filePath = getCachePath(key)
    try {
      const content = await fs.readFile(filePath, "utf-8")
      return JSON.parse(content) as Record<string, unknown>
    } catch {
      return BUNDLED_CATALOGS[key]
    }
  }).pipe(Effect.catch(() => Effect.succeed(BUNDLED_CATALOGS[key])))

/** Lee el snapshot bundled de una clave (sin tocar la cache en disco). */
export const readBundled = (key: string): Effect.Effect<Record<string, unknown> | undefined, never> =>
  Effect.succeed(BUNDLED_CATALOGS[key])

/** Guarda un catálogo en la cache local. */
export const writeCached = (key: string, data: Record<string, unknown>): Effect.Effect<void, never> =>
  Effect.tryPromise(async () => {
    const dir = getCacheDir()
    await fs.mkdir(dir, { recursive: true })
    const filePath = getCachePath(key)
    await fs.writeFile(filePath, JSON.stringify(data), "utf-8")
  }).pipe(Effect.catch(() => Effect.void))

/** Verifica si existe una cache o snapshot para la clave. */
export const hasCached = (key: string): Effect.Effect<boolean, never> =>
  Effect.tryPromise(async () => {
    const filePath = getCachePath(key)
    try {
      await fs.access(filePath)
      return true
    } catch {
      return key in BUNDLED_CATALOGS
    }
  }).pipe(Effect.catch(() => Effect.succeed(key in BUNDLED_CATALOGS)))

/** Elimina toda la cache de compliance. */
export const clearCache = (): Effect.Effect<void, never> =>
  Effect.tryPromise(async () => {
    const dir = getCacheDir()
    await fs.rm(dir, { recursive: true, force: true })
  }).pipe(Effect.catch(() => Effect.void))
