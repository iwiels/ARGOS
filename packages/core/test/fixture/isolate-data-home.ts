/**
 * Aislamiento de datos para TODA la suite de core: cada `bun test` corre con
 * HOME/XDG_DATA/XDG_STATE desechables, así ningún test lee o escribe la BD,
 * el event store ni los proyectos reales del desarrollador.
 *
 * XDG_CACHE_HOME se conserva a propósito: las herramientas descargadas
 * (p. ej. el binario de fff para file.search) viven en cache/bin y
 * re-descargarlas en cada run rompe los timeouts.
 *
 * Debe ejecutarse antes de que cualquier archivo importe src/global.ts
 * (xdg-basedir congela el env al primer import).
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const home = mkdtempSync(join(tmpdir(), "argos-core-tests-"))

process.env.OPENCODE_TEST_HOME ??= home
process.env.XDG_DATA_HOME ??= join(home, "xdg-data")
process.env.XDG_STATE_HOME ??= join(home, "xdg-state")
