import { join } from "node:path"

/**
 * Variables de entorno estáticas del proceso principal, separadas de
 * `server.ts` a propósito: `server.ts` importa `electron`, lo que rompe
 * `bun test` fuera de un runtime Electron real. Esta parte no depende de
 * `electron` y sí puede probarse directamente.
 */
export function staticAppEnv(userDataPath: string): Record<string, string> {
  return {
    // Argos audita repositorios de clientes que no controlamos. Sin
    // esto, el descubrimiento de skills de opencode escanea .claude/.agents
    // tanto en el HOME del operador como, más grave, subiendo desde el
    // propio directorio/worktree que se está auditando (ver
    // packages/argos/src/skill/index.ts, discoverSkills/externalDirs).
    // Un SKILL.md plantado en el repo del cliente (a propósito o por un
    // compromiso previo) se cargaría y ejecutaría como si fuera nuestro,
    // con las mismas instrucciones que vería el agente — supply chain vía
    // el propio objetivo de la auditoría. Las skills de Argos viven
    // únicamente bajo OPENCODE_CONFIG_DIR (argos-config/skills/**),
    // que se recorre por una vía completamente distinta y no se ve
    // afectada por esta bandera.
    ARGOS_DISABLE_EXTERNAL_SKILLS: "true",
    OPENCODE_DISABLE_EXTERNAL_SKILLS: "true",
    ARGOS_EXPERIMENTAL_ICON_DISCOVERY: "true",
    OPENCODE_EXPERIMENTAL_ICON_DISCOVERY: "true",
    ARGOS_EXPERIMENTAL_FILEWATCHER: "true",
    OPENCODE_EXPERIMENTAL_FILEWATCHER: "true",
    ARGOS_CLIENT: "desktop",
    OPENCODE_CLIENT: "desktop",
    XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME ?? join(userDataPath, "config"),
    XDG_DATA_HOME: process.env.XDG_DATA_HOME ?? join(userDataPath, "data"),
    XDG_CACHE_HOME: process.env.XDG_CACHE_HOME ?? join(userDataPath, "cache"),
    XDG_STATE_HOME: process.env.XDG_STATE_HOME ?? userDataPath,
  }
}
