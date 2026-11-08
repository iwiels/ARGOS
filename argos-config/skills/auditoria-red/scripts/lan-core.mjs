import { parseArgs } from "util";
import net from "net";
import { fileURLToPath } from "url";
function isEntryPoint() {
  try {
    return !!process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
  } catch {
    return false;
  }
}
const COMMON_PORTS = [
  21,
  22,
  23,
  25,
  53,
  80,
  110,
  111,
  135,
  139,
  143,
  443,
  445,
  465,
  587,
  993,
  995,
  1433,
  1521,
  2049,
  3e3,
  3306,
  3389,
  5432,
  5900,
  5985,
  6379,
  8e3,
  8080,
  8443,
  9090,
  9200,
  27017
];
const MAX_HOSTS = 4096;
const HOST_CONCURRENCY = 64;
async function scanPort(host, port) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    s.setTimeout(800);
    s.on("connect", () => {
      s.destroy();
      resolve(port);
    });
    s.on("timeout", () => {
      s.destroy();
      resolve(null);
    });
    s.on("error", () => {
      resolve(null);
    });
    s.connect(port, host);
  });
}
function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  return (parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]) >>> 0;
}
function intToIp(int) {
  return [int >>> 24 & 255, int >>> 16 & 255, int >>> 8 & 255, int & 255].join(".");
}
function generateIPs(cidr) {
  const [base, prefixRaw] = cidr.split("/");
  const prefix = parseInt(prefixRaw ?? "32", 10);
  if (!net.isIPv4(base) || Number.isNaN(prefix) || prefix < 0 || prefix > 32) {
    return { ips: [base], truncated: false };
  }
  if (prefix === 32) return { ips: [base], truncated: false };
  const hostBits = 32 - prefix;
  const totalHosts = 2 ** hostBits;
  const networkInt = ipToInt(base) & ~0 << hostBits >>> 0;
  const firstOffset = hostBits >= 2 ? 1 : 0;
  const lastOffset = hostBits >= 2 ? totalHosts - 2 : totalHosts - 1;
  const usableHosts = lastOffset - firstOffset + 1;
  const cappedHosts = Math.min(usableHosts, MAX_HOSTS);
  const truncated = cappedHosts < usableHosts;
  const ips = [];
  for (let i = 0; i < cappedHosts; i++) {
    ips.push(intToIp(networkInt + firstOffset + i));
  }
  return { ips, truncated };
}
async function main() {
  const { positionals } = parseArgs({ args: process.argv.slice(2), strict: false });
  let target = positionals[0];
  if (!target) {
    console.error(JSON.stringify({ error: "No target provided. Usage: node lan-core.mjs <CIDR/IP>" }));
    process.exit(1);
  }
  console.log(JSON.stringify({
    status: "progress",
    message: `Iniciando auditor\xEDa de red LAN (fallback local, sin ARP/identificaci\xF3n de fabricante) en ${target}`
  }));
  const report = {
    target,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    degraded: true,
    degraded_reason: "Ejecutado con el fallback lan-core (TCP-connect puro). El MCP nativo argos-lan (ARP, MAC/fabricante, mDNS, SNMP) no estaba disponible.",
    hosts: [],
    findings: [],
    topology_ready: false,
    scan_truncated: false
  };
  const { ips: ipsToScan, truncated } = target.includes("/") ? generateIPs(target) : { ips: [target], truncated: false };
  report.scan_truncated = truncated;
  console.log(JSON.stringify({
    status: "progress",
    message: truncated ? `Escaneando ${ipsToScan.length} IPs (rango truncado a ${MAX_HOSTS} hosts por l\xEDmite de seguridad del fallback)...` : `Escaneando ${ipsToScan.length} IPs...`
  }));
  try {
    const activeHosts = [];
    for (let i = 0; i < ipsToScan.length; i += HOST_CONCURRENCY) {
      const batch = ipsToScan.slice(i, i + HOST_CONCURRENCY);
      const batchResults = await Promise.all(
        batch.map(async (ip) => {
          const portPromises = COMMON_PORTS.map((p) => scanPort(ip, p));
          const results = await Promise.all(portPromises);
          const openPorts = results.filter((r) => r !== null);
          return openPorts.length > 0 ? { ip, openPorts } : null;
        })
      );
      for (const host of batchResults) if (host) activeHosts.push(host);
    }
    report.hosts = activeHosts;
    console.log(JSON.stringify({ status: "progress", message: `Se detectaron ${activeHosts.length} hosts activos.` }));
    for (const host of activeHosts) {
      const ports = host.openPorts;
      report.findings.push({
        severity: "info",
        title: "Host Activo con Puertos Abiertos",
        evidence: `${host.ip}: puertos ${ports.join(", ")}`,
        remediation: "Confirmar que todos los servicios expuestos est\xE1n autorizados y son necesarios (superficie m\xEDnima).",
        tags: ["open-ports", "port-scan", "service-discovery"]
      });
      if (ports.includes(445) || ports.includes(139)) {
        report.findings.push({
          severity: "info",
          title: "Servicio SMB Expuesto en LAN",
          evidence: `TCP/${ports.includes(445) ? "445" : "139"} abierto en ${host.ip}`,
          remediation: "Asegure que solo hosts autorizados puedan comunicarse v\xEDa SMB. Desactive SMBv1.",
          tags: ["open-ports", "smb-share", "exposed-service"],
          cwe: "552"
        });
      }
      if (ports.includes(3389)) {
        report.findings.push({
          severity: "high",
          title: "Escritorio Remoto (RDP) Detectado",
          evidence: `TCP/3389 abierto en ${host.ip}`,
          remediation: "Utilice NLA (Network Level Authentication) y restrinja el acceso RDP mediante VPN.",
          tags: ["open-ports", "rdp", "exposed-service"]
        });
      }
      if (ports.includes(5900)) {
        report.findings.push({
          severity: "high",
          title: "VNC Expuesto",
          evidence: `TCP/5900 abierto en ${host.ip}`,
          remediation: "Restrinja el acceso VNC mediante VPN y exija autenticaci\xF3n fuerte; VNC sin cifrar expone credenciales.",
          tags: ["open-ports", "vpn", "exposed-service", "cleartext"]
        });
      }
      if (ports.includes(21) || ports.includes(23)) {
        report.findings.push({
          severity: "critical",
          title: "Protocolo de Texto Plano (FTP/Telnet)",
          evidence: `Puertos ${[ports.includes(21) ? 21 : null, ports.includes(23) ? 23 : null].filter(Boolean).join(" y ")} abiertos en ${host.ip}`,
          remediation: "Sustituir FTP por SFTP y Telnet por SSH. Estos protocolos env\xEDan credenciales sin cifrar.",
          tags: ["cleartext", "plaintext", "open-ports", "exposed-service"],
          cwe: "319"
        });
      }
      for (const [port, name] of [[3306, "MySQL"], [5432, "PostgreSQL"], [27017, "MongoDB"], [6379, "Redis"]]) {
        if (ports.includes(port)) {
          report.findings.push({
            severity: "high",
            title: `Base de Datos ${name} Expuesta en LAN`,
            evidence: `TCP/${port} (${name}) abierto en ${host.ip}`,
            remediation: `Restrinja ${name} a localhost o a una red de aplicaci\xF3n segmentada; nunca deber\xEDa ser alcanzable desde toda la LAN.`,
            tags: ["open-ports", "exposed-service", "network-config"]
          });
        }
      }
    }
    report.topology_ready = true;
    console.log(JSON.stringify({ status: "done", report }, null, 2));
  } catch (error) {
    console.error(JSON.stringify({ error: String(error) }));
    process.exit(1);
  }
}
if (isEntryPoint()) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
export {
  MAX_HOSTS,
  generateIPs,
  intToIp,
  ipToInt
};
