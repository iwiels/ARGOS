/**
 * Stories harness config. Standalone from the package's vite.config.ts on
 * purpose: ui sources use the "@" alias expecting to be bundled against THIS
 * package's src (consumers historically resolved it with their own alias).
 */
import { fileURLToPath } from "node:url"
import { defineConfig } from "vite"
import solid from "vite-plugin-solid"

export default defineConfig({
  plugins: [solid()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("../src", import.meta.url)),
    },
  },
  server: { port: 3002 },
  build: { target: "esnext" },
})
