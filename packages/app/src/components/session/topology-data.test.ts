import { describe, expect, test } from "bun:test"
import {
  selectTopologySnapshot,
  isLanTool,
  hasTopologyData,
  extractLanPartsFromMessages,
  topologyPartsFromFindings,
  TOPOLOGY_SNAPSHOT_TAG,
  type LanToolPart,
} from "./topology-data"
import type { Finding } from "./findings-data"

const part = (tool: string, output: string, status = "completed"): LanToolPart => ({ tool, status, output })

// Salida real capturada de argos-lan.exe build_topology (post-scan).
const BUILD_TOPOLOGY = JSON.stringify({
  total_hosts: 4,
  categories: {
    gateways: ["192.168.18.1"],
    servers: null,
    workstations: ["192.168.18.86", "192.168.18.80"],
    iot: null,
    mobile: null,
    printers: null,
    unknown: ["192.168.18.2"],
  },
  risky_summary: {
    telnet_open: null,
    rdp_open: null,
    vnc_open: null,
    smb_open: null,
    redis_open: null,
    mongo_open: null,
    docker_open: null,
    snmp_responded: null,
  },
  hosts: [
    { ip: "192.168.18.86", mac: "70:9C:D1:68:A1:AA", hostname: "", vendor: "Intel Corporate", methods: ["arp"] },
    { ip: "192.168.18.1", mac: "A0:40:6F:96:85:28", hostname: "dev.opt", vendor: "HUAWEI", methods: ["arp"] },
    { ip: "192.168.18.2", mac: "9E:9D:7E:05:02:F4", hostname: "", vendor: "", methods: ["arp"] },
    { ip: "192.168.18.80", mac: "20:17:42:99:C8:13", hostname: "", vendor: "LG Electronics", methods: ["arp"] },
  ],
})

const HOST_DISCOVERY = JSON.stringify({
  cidr: "192.168.18.9/24",
  hosts: [
    { ip: "192.168.18.80", mac: "20:17:42:99:C8:13", vendor: "LG Electronics", method: "arp" },
    { ip: "192.168.18.1", mac: "A0:40:6F:96:85:28", vendor: "HUAWEI", method: "arp" },
  ],
  hosts_discovered: 2,
})

describe("selectTopologySnapshot", () => {
  test("parses build_topology into devices + gateway", () => {
    const snap = selectTopologySnapshot([part("argos-lan_build_topology", BUILD_TOPOLOGY)])
    expect(snap).toBeDefined()
    expect(snap!.totalHosts).toBe(4)
    expect(snap!.gateway?.ip).toBe("192.168.18.1")
    expect(snap!.gateway?.hostname).toBe("dev.opt")
    // El gateway no aparece en la lista de devices.
    expect(snap!.devices.map((d) => d.ip)).not.toContain("192.168.18.1")
    expect(snap!.devices).toHaveLength(3)
    const intel = snap!.devices.find((d) => d.ip === "192.168.18.86")
    expect(intel?.vendor).toBe("Intel Corporate")
    expect(intel?.info).toBe("topology.category.workstations")
    // hostname vacío del MCP se normaliza a undefined.
    expect(intel?.hostname).toBeUndefined()
  })

  test("derives risky open ports from risky_summary", () => {
    const data = JSON.parse(BUILD_TOPOLOGY)
    data.risky_summary.rdp_open = ["192.168.18.80"]
    data.risky_summary.telnet_open = ["192.168.18.2"]
    const snap = selectTopologySnapshot([part("argos-lan_build_topology", JSON.stringify(data))])
    expect(snap!.devices.find((d) => d.ip === "192.168.18.80")?.openPorts).toContain(3389)
    expect(snap!.devices.find((d) => d.ip === "192.168.18.2")?.openPorts).toContain(23)
    expect(snap!.risky.map((r) => r.label).sort()).toEqual(["RDP", "Telnet"])
  })

  test("falls back to host_discovery when no topology", () => {
    const snap = selectTopologySnapshot([part("argos-lan_host_discovery", HOST_DISCOVERY)])
    expect(snap).toBeDefined()
    expect(snap!.totalHosts).toBe(2)
    expect(snap!.devices).toHaveLength(2)
    expect(snap!.gateway).toBeUndefined()
  })

  test("prefers build_topology over host_discovery", () => {
    const snap = selectTopologySnapshot([
      part("argos-lan_host_discovery", HOST_DISCOVERY),
      part("argos-lan_build_topology", BUILD_TOPOLOGY),
    ])
    expect(snap!.gateway?.ip).toBe("192.168.18.1")
    expect(snap!.devices).toHaveLength(3)
  })

  test("uses the latest build_topology", () => {
    const newer = JSON.parse(BUILD_TOPOLOGY)
    newer.hosts = [{ ip: "10.0.0.5", vendor: "NewHost", methods: ["arp"] }]
    newer.categories = { gateways: [], unknown: ["10.0.0.5"] }
    newer.total_hosts = 1
    const snap = selectTopologySnapshot([
      part("argos-lan_build_topology", BUILD_TOPOLOGY),
      part("argos-lan_build_topology", JSON.stringify(newer)),
    ])
    expect(snap!.devices.map((d) => d.ip)).toEqual(["10.0.0.5"])
  })

  test("ignores 'no data' topology and pending parts", () => {
    const empty = selectTopologySnapshot([
      part("argos-lan_build_topology", '{"error":"No hay datos de topología."}'),
      part("argos-lan_host_discovery", HOST_DISCOVERY, "running"),
    ])
    expect(empty).toBeUndefined()
  })

  test("returns undefined when there are no lan parts", () => {
    expect(selectTopologySnapshot([part("read", "some file")])).toBeUndefined()
    expect(selectTopologySnapshot([])).toBeUndefined()
  })
})

describe("isLanTool", () => {
  test("identifies LAN and network tools", () => {
    expect(isLanTool("argos-lan_build_topology")).toBe(true)
    expect(isLanTool("argos-lan_host_discovery")).toBe(true)
    expect(isLanTool("argos-lan_port_scan")).toBe(true)
    expect(isLanTool("argos-lan_banner_grab")).toBe(true)
    expect(isLanTool("argos-lan_custom_tool")).toBe(true)
    expect(isLanTool("read_file")).toBe(false)
    expect(isLanTool("argos_memory_save")).toBe(false)
  })

  test("selects a snapshot from the new argos-lan tool names", () => {
    const snap = selectTopologySnapshot([part("argos-lan_build_topology", BUILD_TOPOLOGY)])
    expect(snap?.devices.length).toBeGreaterThan(0)
  })
})

describe("hasTopologyData", () => {
  test("returns false when no parts or non-LAN parts", () => {
    expect(hasTopologyData([])).toBe(false)
    expect(hasTopologyData([part("read_file", "output")])).toBe(false)
  })

  test("returns true when LAN scan parts exist", () => {
    expect(hasTopologyData([part("argos-lan_host_discovery", HOST_DISCOVERY)])).toBe(true)
    expect(hasTopologyData([part("argos-lan_port_scan", "{}")])).toBe(true)
  })
})

describe("extractLanPartsFromMessages", () => {
  test("extracts LAN tool parts from messages store", () => {
    const messages = [{ id: "m1" }, { id: "m2" }]
    const partStore = {
      m1: [
        { type: "tool", tool: "read_file", state: { status: "completed", output: "some text" } },
        { type: "tool", tool: "argos-lan_host_discovery", state: { status: "completed", output: HOST_DISCOVERY } },
      ],
      m2: [
        { type: "tool", tool: "argos-lan_port_scan", state: { status: "completed", output: "{}" } },
      ],
    }

    const parts = extractLanPartsFromMessages(messages, partStore)
    expect(parts).toHaveLength(2)
    expect(parts[0].tool).toBe("argos-lan_host_discovery")
    expect(parts[1].tool).toBe("argos-lan_port_scan")
  })
})

describe("topologyPartsFromFindings", () => {
  const topologyFinding = (overrides: Partial<Finding> = {}): Finding => ({
    title: "Mapa de topología de red",
    severity: "info",
    source: "memory",
    tags: [TOPOLOGY_SNAPSHOT_TAG],
    evidence: BUILD_TOPOLOGY,
    ...overrides,
  })

  test("converts a tagged finding into a synthetic LanToolPart that selectTopologySnapshot can read", () => {
    const parts = topologyPartsFromFindings([topologyFinding()])
    expect(parts).toHaveLength(1)
    expect(parts[0].status).toBe("completed")

    const snapshot = selectTopologySnapshot(parts)
    expect(snapshot?.devices.length).toBeGreaterThan(0)
    expect(snapshot?.gateway?.ip).toBe("192.168.18.1")
  })

  test("ignores findings without the topology-snapshot tag", () => {
    const parts = topologyPartsFromFindings([
      { title: "SQLi en login", severity: "high", source: "memory", evidence: BUILD_TOPOLOGY },
      topologyFinding({ tags: ["some-other-tag"] }),
    ])
    expect(parts).toHaveLength(0)
  })

  test("ignores a tagged finding with no evidence or raw to parse", () => {
    const parts = topologyPartsFromFindings([topologyFinding({ evidence: undefined, raw: undefined })])
    expect(parts).toHaveLength(0)
  })

  test("falls back to raw when evidence is absent", () => {
    const parts = topologyPartsFromFindings([topologyFinding({ evidence: undefined, raw: BUILD_TOPOLOGY })])
    const snapshot = selectTopologySnapshot(parts)
    expect(snapshot?.gateway?.ip).toBe("192.168.18.1")
  })

  test("cross-agent reconciled findings merge with live session parts in the same snapshot selection", () => {
    const reconciled = topologyPartsFromFindings([topologyFinding()])
    const live = [part("argos-lan_host_discovery", HOST_DISCOVERY)]
    const snapshot = selectTopologySnapshot([...reconciled, ...live])
    // build_topology (reconciled) outranks host_discovery (live) per selectTopologySnapshot's priority.
    expect(snapshot?.gateway?.ip).toBe("192.168.18.1")
  })
})


