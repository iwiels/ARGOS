/**
 * DOM component tests (Vitest + happy-dom + solid plugin).
 *
 * Lives outside bun on purpose: bun 1.3.x cannot emit solid-compatible JSX
 * for DOM tests on this platform, while Vite can. Files live in tests/dom/
 * so `bun test src` never discovers them; run via `pnpm test:dom`.
 */
import { fileURLToPath } from "node:url"
import solid from "vite-plugin-solid"
import { defineConfig } from "vitest/config"

export default defineConfig({
  plugins: [solid({ dev: false, hot: false })],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "happy-dom",
    include: ["tests/dom/**/*.test.tsx"],
    setupFiles: ["tests/dom/setup.ts"],
  },
})
