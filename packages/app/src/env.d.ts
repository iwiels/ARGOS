/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ARGOS_SERVER_HOST?: string
  readonly VITE_ARGOS_SERVER_PORT?: string
  readonly VITE_ARGOS_CHANNEL?: "dev" | "beta" | "prod"
  readonly ARGOS_CHANNEL?: "dev" | "beta" | "prod"

  readonly VITE_OPENCODE_SERVER_HOST?: string
  readonly VITE_OPENCODE_SERVER_PORT?: string
  readonly VITE_OPENCODE_CHANNEL?: "dev" | "beta" | "prod"
  readonly OPENCODE_CHANNEL?: "dev" | "beta" | "prod"

  readonly VITE_SENTRY_DSN?: string
  readonly VITE_SENTRY_ENVIRONMENT?: string
  readonly VITE_SENTRY_RELEASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

import "solid-js"
declare module "solid-js" {
  namespace JSX {
    interface Directives {
      sortable: boolean
    }
  }
}


