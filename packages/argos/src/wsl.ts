import * as Log from "@argos/core/util/log"
import { Server } from "./server/server"

const port = Number.parseInt(process.env.ARGOS_PORT ?? "4096", 10)
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("ARGOS_PORT must be a valid TCP port")
if (!process.env.ARGOS_SERVER_PASSWORD) throw new Error("ARGOS_SERVER_PASSWORD is required")

await Log.init({ print: false, level: "WARN" })
const listener = await Server.listen({
  hostname: "0.0.0.0",
  port,
  cors: ["oc://renderer"],
})
Log.Default.info("Linux Argos server ready", { hostname: listener.hostname, port: listener.port })

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    void listener.stop().finally(() => process.exit(0))
  })
}
