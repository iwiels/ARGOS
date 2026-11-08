/**
 * topology-data.ts
 *
 * Parser puro (sin dependencias de Solid/SDK) que convierte la salida real de
 * las tools del MCP `argos-lan` en el modelo `Device[]` que consume
 * TopologyCanvas. Mantenerlo puro lo hace testeable y evita acoplar el canvas
 * al formato del motor de red.
 *
 * Formatos de entrada confirmados (argos-lan.exe):
 *
 *  build_topology  → { total_hosts, categories:{gateways,servers,workstations,
 *                      iot,mobile,printers,unknown}, risky_summary:{telnet_open,
 *                      rdp_open,...}, hosts:[{ip,mac,hostname,vendor,methods,
 *                      openPorts?}] }
 *  host_discovery  → { cidr, hosts:[{ip,mac,vendor,method}], hosts_discovered }
 */

export const DEFAULT_RISKY_PORTS = new Set([21, 22, 23, 80, 445, 1433, 3389, 5555, 5900, 8080, 8554, 9090, 11311])

export interface Device {
  ip: string
  mac?: string
  vendor?: string
  hostname?: string
  /** Etiqueta de categoría (Gateway, Workstation, IoT, …) cuando está disponible. */
  info?: string
  openPorts?: number[]
}

export interface RiskGroup {
  label: string
  ips: string[]
}

export interface TopologySnapshot {
  devices: Device[]
  gateway?: Device
  totalHosts: number
  risky: RiskGroup[]
}

/** Entrada mínima desacoplada del SDK: lo que necesitamos de cada ToolPart. */
export interface LanToolPart {
  tool: string
  status: string
  output: string
}

import { normalizeToolPart, type Finding } from "./findings-data"

export const BUILD_TOPOLOGY_TOOL = "argos-lan_build_topology"
export const HOST_DISCOVERY_TOOL = "argos-lan_host_discovery"

const EMPTY_FINDINGS: Finding[] = []

function hashStringInto(seed: number, value: string): number {
  let h = seed
  const len = value.length
  const window = Math.min(len, 96)
  for (let i = 0; i < window; i++) h = Math.imul(h ^ value.charCodeAt(i), 16777619)
  h = Math.imul(h ^ len, 16777619)
  for (let i = len - window; i < len; i++) h = Math.imul(h ^ value.charCodeAt(i), 16777619)
  return h
}

function hashNumberInto(h: number, value: number): number {
  return Math.imul(h ^ (value | 0), 16777619)
}

function hashValueInto(h: number, value: unknown, depth: number): number {
  if (value === undefined) return Math.imul(h ^ 5, 16777619)
  if (value === null) return Math.imul(h ^ 3, 16777619)
  switch (typeof value) {
    case "string":
      return hashStringInto(h, value)
    case "number":
      return hashNumberInto(h, value)
    case "boolean":
      return Math.imul(h ^ (value ? 7 : 11), 16777619)
    case "object": {
      if (depth > 4) return Math.imul(h ^ 13, 16777619)
      if (Array.isArray(value)) {
        h = Math.imul(h ^ 17, 16777619)
        h = hashNumberInto(h, value.length)
        const count = Math.min(value.length, 32)
        for (let i = 0; i < count; i++) h = hashValueInto(h, value[i], depth + 1)
        return h
      }
      const entries = Object.entries(value as Record<string, unknown>)
      h = Math.imul(h ^ 19, 16777619)
      h = hashNumberInto(h, entries.length)
      const count = Math.min(entries.length, 64)
      for (let i = 0; i < count; i++) {
        const entry = entries[i]
        if (!entry) continue
        h = hashStringInto(h, entry[0])
        h = hashValueInto(h, entry[1], depth + 1)
      }
      return h
    }
    default:
      return Math.imul(h ^ 23, 16777619)
  }
}

/**
 * Cheap change-detector over a raw store-backed parts array. Hashes exactly the
 * fields the findings/topology parsers consume (tool, status, input, output),
 * so unrelated streamed mutations (e.g. text part growth) leave it untouched.
 */
export function extractedToolPartsSignature(rawParts: readonly unknown[] | undefined): number {
  if (!rawParts) return (0x811c9dc4 ^ 0x9e3779b9) >>> 0
  let h = hashNumberInto(0x811c9dc4, rawParts.length)
  for (let i = 0; i < rawParts.length; i++) {
    const part = normalizeToolPart(rawParts[i])
    if (!part) continue
    h = Math.imul(h ^ 31, 16777619)
    h = hashStringInto(h, part.tool)
    h = hashStringInto(h, part.status)
    if (part.input) {
      h = Math.imul(h ^ 37, 16777619)
      h = hashValueInto(h, part.input, 0)
    }
    if (part.output !== undefined) {
      h = Math.imul(h ^ 41, 16777619)
      h = hashStringInto(h, part.output)
    }
  }
  return h >>> 0
}

export interface TopologySnapshotSourceInput {
  sessionId: string
  messages: { id: string }[]
  partStore: Record<string, unknown[] | undefined>
  apiFindings?: Finding[]
}

/**
 * Per-session caching wrapper around extractLanPartsFromMessages +
 * selectTopologySnapshot. Store-backed part arrays mutate in place (see
 * context/global-sync/event-reducer.ts reconcile/delta paths), so caching is
 * keyed on content signatures instead of array identity.
 */
export function createTopologySnapshotSource() {
  const liveCache = new Map<string, { sig: number; live: LanToolPart[] }>()
  const snapCache = new Map<
    string,
    { api: Finding[] | undefined; live: LanToolPart[]; snapshot: TopologySnapshot | undefined }
  >()

  return (input: TopologySnapshotSourceInput): TopologySnapshot | undefined => {
    const { sessionId, messages, partStore } = input
    const apiFindings = input.apiFindings
    let sig = 0x811c9dc4
    for (const message of messages) {
      sig = Math.imul(sig ^ hashStringInto(0x9dc5, message.id), 16777619)
      sig = Math.imul(sig ^ extractedToolPartsSignature(partStore[message.id]), 16777619)
    }
    sig = sig >>> 0

    const liveEntry = liveCache.get(sessionId)
    let live: LanToolPart[]
    if (liveEntry && liveEntry.sig === sig) {
      live = liveEntry.live
    } else {
      live = extractLanPartsFromMessages(messages, partStore)
      liveCache.set(sessionId, { sig, live })
      if (liveCache.size > 128) liveCache.clear()
    }

    const snapEntry = snapCache.get(sessionId)
    if (snapEntry && snapEntry.api === apiFindings && snapEntry.live === live) return snapEntry.snapshot
    const snapshot = selectTopologySnapshot([...topologyPartsFromFindings(apiFindings ?? EMPTY_FINDINGS), ...live])
    snapCache.set(sessionId, { api: apiFindings, live, snapshot })
    if (snapCache.size > 128) snapCache.clear()
    return snapshot
  }
}

/**
 * Tag que un agente (típicamente security-ops corriendo el escaneo de red)
 * pone en su `argos_memory_save` cuando la evidencia es el JSON crudo de
 * `build_topology`/`host_discovery`, no una descripción en prosa.
 *
 * Por qué existe: cuando ese agente corre fuera del proceso que trackea la
 * sesión que el usuario está viendo (ver AGENTS.md — modelo "team peers", no
 * subagentes con sesión hija real), sus tool-calls de argos-lan nunca
 * aparecen como `LanToolPart` en vivo de ESTA sesión — solo se puentean acá
 * vía la misma reconciliación de hallazgos que ya trae hallazgos cross-agente
 * (`argos_session_id`, ver packages/core/src/security/agent-findings-reconcile.ts).
 * Sin esto, el panel de Topología queda vacío para cualquier escaneo de red
 * que no haya corrido literalmente en el turno del orquestador.
 */
export const TOPOLOGY_SNAPSHOT_TAG = "topology-snapshot"

/**
 * Convierte hallazgos reconciliados (cross-agente, vía memoria compartida) que
 * llevan `TOPOLOGY_SNAPSHOT_TAG` en `LanToolPart`s sintéticas, para que fluyan
 * por el mismo parser (`selectTopologySnapshot`) que ya usan las tool-parts en
 * vivo. Nunca falla: un finding cuya evidencia no es JSON parseable se ignora.
 */
export function topologyPartsFromFindings(findings: Finding[]): LanToolPart[] {
  const parts: LanToolPart[] = []
  for (const finding of findings) {
    if (!finding.tags?.includes(TOPOLOGY_SNAPSHOT_TAG)) continue
    const output = finding.evidence ?? finding.raw
    if (!output) continue
    parts.push({ tool: BUILD_TOPOLOGY_TOOL, status: "completed", output })
  }
  return parts
}

export const LAN_TOOL_PREFIXES = ["argos-lan_"]

export const LAN_TOOLS = new Set([
  BUILD_TOPOLOGY_TOOL,
  HOST_DISCOVERY_TOOL,
  "argos-lan_port_scan",
  "argos-lan_banner_grab",
  "argos-lan_snmp_query",
  "argos-lan_mdns_discover",
])

export function isLanTool(tool: string): boolean {
  return LAN_TOOLS.has(tool) || LAN_TOOL_PREFIXES.some((prefix) => tool.startsWith(prefix))
}

export function extractLanPartsFromMessages(
  messages: { id: string }[],
  partStore: Record<string, unknown[] | undefined>,
): LanToolPart[] {
  const parts: LanToolPart[] = []
  for (const msg of messages) {
    const msgParts = partStore[msg.id] ?? []
    for (const rawPart of msgParts) {
      const p = normalizeToolPart(rawPart)
      if (p && isLanTool(p.tool)) {
        parts.push({ tool: p.tool, status: p.status, output: p.output ?? "" })
      }
    }
  }
  return parts
}

export function hasTopologyData(parts: LanToolPart[]): boolean {
  if (!parts || parts.length === 0) return false
  const snap = selectTopologySnapshot(parts)
  if (snap && (snap.devices.length > 0 || snap.gateway)) return true
  return parts.some((p) => isLanTool(p.tool))
}

const RISKY_SUMMARY_PORTS: Record<string, number> = {
  telnet_open: 23,
  rdp_open: 3389,
  vnc_open: 5900,
  smb_open: 445,
  redis_open: 6379,
  mongo_open: 27017,
  docker_open: 2375,
  snmp_responded: 161,
}

const RISKY_SUMMARY_LABELS: Record<string, string> = {
  telnet_open: "Telnet",
  rdp_open: "RDP",
  vnc_open: "VNC",
  smb_open: "SMB",
  redis_open: "Redis",
  mongo_open: "MongoDB",
  docker_open: "Docker",
  snmp_responded: "SNMP",
}

/** Claves i18n para las categorías de dispositivos (traducir con language.t). */
export const CATEGORY_LABELS: Record<string, string> = {
  gateways: "topology.category.gateways",
  servers: "topology.category.servers",
  workstations: "topology.category.workstations",
  iot: "topology.category.iot",
  mobile: "topology.category.mobile",
  printers: "topology.category.printers",
  unknown: "topology.category.unknown",
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function parseJsonLoose(output: string): unknown {
  const text = output?.trim()
  if (!text) return undefined
  try {
    return JSON.parse(text)
  } catch {
    // El MCP puede anteponer/anexar texto; intentar extraer el bloque JSON.
    const start = text.indexOf("{")
    const end = text.lastIndexOf("}")
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(text.slice(start, end + 1))
      } catch {
        return undefined
      }
    }
    return undefined
  }
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined
}

function toPorts(value: unknown): number[] | undefined {
  if (!Array.isArray(value)) return undefined
  const ports = value.map((p) => Number(p)).filter((p) => Number.isFinite(p) && p > 0)
  return ports.length ? [...new Set(ports)].sort((a, b) => a - b) : undefined
}

function hostPorts(host: Record<string, unknown>): number[] | undefined {
  return toPorts(host.openPorts) ?? toPorts(host.open_ports) ?? toPorts(host.ports) ?? toPorts(host.tcp_ports)
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((x): x is string => typeof x === "string") : []
}

function fromBuildTopology(data: unknown): TopologySnapshot | undefined {
  if (!isRecord(data)) return undefined
  const hosts = Array.isArray(data.topology) ? data.topology : data.hosts
  if (!Array.isArray(hosts)) return undefined

  const categories = isRecord(data.categories) ? data.categories : {}
  const categoryByIp = new Map<string, string>()
  for (const [key, ips] of Object.entries(categories)) {
    const label = CATEGORY_LABELS[key] ?? key
    for (const ip of stringArray(ips)) categoryByIp.set(ip, label)
  }
  const gatewayIps = new Set(stringArray(categories.gateways))

  const riskyPortsByIp = new Map<string, Set<number>>()
  const risky: RiskGroup[] = []

  const summary = isRecord(data.risky_summary) ? data.risky_summary : {}
  for (const [key, value] of Object.entries(summary)) {
    const ips = stringArray(value)
    if (ips.length === 0) continue
    risky.push({ label: RISKY_SUMMARY_LABELS[key] ?? key, ips })
    const port = RISKY_SUMMARY_PORTS[key]
    if (!port) continue
    for (const ip of ips) {
      const set = riskyPortsByIp.get(ip) ?? new Set<number>()
      set.add(port)
      riskyPortsByIp.set(ip, set)
    }
  }

  if (Array.isArray(data.risks)) {
    const groupedRisks = new Map<string, string[]>()
    for (const raw of data.risks) {
      if (!isRecord(raw)) continue
      const ip = str(raw.ip)
      const riskName = str(raw.risk) || "Risk"
      if (!ip) continue

      const arr = groupedRisks.get(riskName) ?? []
      if (!arr.includes(ip)) arr.push(ip)
      groupedRisks.set(riskName, arr)

      const port = Number(raw.port)
      if (Number.isFinite(port) && port > 0) {
        const set = riskyPortsByIp.get(ip) ?? new Set<number>()
        set.add(port)
        riskyPortsByIp.set(ip, set)
      }
    }
    for (const [label, ips] of groupedRisks.entries()) {
      risky.push({ label, ips })
    }
  }

  const devices: Device[] = []
  let gateway: Device | undefined
  for (const raw of hosts) {
    if (!isRecord(raw)) continue
    const ip = str(raw.ip)
    if (!ip) continue
    const ports = new Set(hostPorts(raw) ?? [])
    for (const port of riskyPortsByIp.get(ip) ?? []) ports.add(port)

    const classLabel = str(raw.classification)
    if (classLabel === "Gateway") gatewayIps.add(ip)

    const device: Device = {
      ip,
      mac: str(raw.mac),
      vendor: str(raw.vendor),
      hostname: str(raw.hostname),
      info: classLabel || categoryByIp.get(ip),
      openPorts: ports.size ? [...ports].sort((a, b) => a - b) : undefined,
    }
    if (gatewayIps.has(ip) && !gateway) gateway = device
    else devices.push(device)
  }

  const summaryRecord = isRecord(data.summary) ? data.summary : undefined
  const totalHosts =
    typeof summaryRecord?.total_hosts === "number"
      ? summaryRecord.total_hosts
      : typeof data.total_hosts === "number"
        ? data.total_hosts
        : devices.length + (gateway ? 1 : 0)

  return { devices, gateway, totalHosts, risky }
}

function fromHostDiscovery(data: unknown): TopologySnapshot | undefined {
  const hosts = Array.isArray(data) ? data : isRecord(data) ? data.hosts : undefined
  if (!Array.isArray(hosts)) return undefined
  const devices: Device[] = []
  for (const raw of hosts) {
    if (!isRecord(raw)) continue
    const ip = str(raw.ip)
    if (!ip) continue
    devices.push({
      ip,
      mac: str(raw.mac),
      vendor: str(raw.vendor),
      hostname: str(raw.hostname),
      openPorts: hostPorts(raw),
    })
  }
  const totalHosts =
    isRecord(data) && typeof data.hosts_discovered === "number" ? data.hosts_discovered : devices.length
  return { devices, totalHosts, risky: [] }
}

/**
 * Selecciona la mejor topología disponible de las tool parts de una sesión.
 * Prioriza el último `build_topology` con datos (incluye categorías y riesgos);
 * si no hay, cae al último `host_discovery`. `parts` se espera en orden
 * cronológico ascendente.
 */
export function selectTopologySnapshot(parts: LanToolPart[]): TopologySnapshot | undefined {
  const completed = parts.filter((p) => p.status === "completed" && typeof p.output === "string")

  for (let i = completed.length - 1; i >= 0; i--) {
    if (completed[i].tool !== BUILD_TOPOLOGY_TOOL) continue
    const data = parseJsonLoose(completed[i].output)
    const snap = data === undefined ? undefined : fromBuildTopology(data)
    if (snap && (snap.devices.length || snap.gateway)) return snap
  }

  for (let i = completed.length - 1; i >= 0; i--) {
    if (completed[i].tool !== HOST_DISCOVERY_TOOL) continue
    const data = parseJsonLoose(completed[i].output)
    const snap = data === undefined ? undefined : fromHostDiscovery(data)
    if (snap && snap.devices.length) return snap
  }

  return undefined
}


