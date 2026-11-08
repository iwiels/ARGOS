interface ImportMetaEnv {
  readonly ARGOS_CHANNEL: string
  readonly OPENCODE_CHANNEL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare module "virtual:argos-server" {
  export namespace Server {
    export const listen: typeof import("../../../argos/dist/types/src/node").Server.listen
    export type Listener = import("../../../argos/dist/types/src/node").Server.Listener
  }
  export namespace Config {
    export const get: typeof import("../../../argos/dist/types/src/node").Config.get
    export type Info = import("../../../argos/dist/types/src/node").Config.Info
  }
  export namespace Log {
    export const init: typeof import("../../../argos/dist/types/src/node").Log.init
  }
  export const bootstrap: typeof import("../../../argos/dist/types/src/node").bootstrap
}

declare module "virtual:opencode-server" {
  export namespace Server {
    export const listen: typeof import("../../../argos/dist/types/src/node").Server.listen
    export type Listener = import("../../../argos/dist/types/src/node").Server.Listener
  }
  export namespace Config {
    export const get: typeof import("../../../argos/dist/types/src/node").Config.get
    export type Info = import("../../../argos/dist/types/src/node").Config.Info
  }
  export namespace Log {
    export const init: typeof import("../../../argos/dist/types/src/node").Log.init
  }
  export const bootstrap: typeof import("../../../argos/dist/types/src/node").bootstrap
}
