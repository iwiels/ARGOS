import { describe, expect, test } from "bun:test";
import { generateIPs, intToIp, ipToInt, MAX_HOSTS } from "./lan-core";

describe("ipToInt / intToIp round-trip", () => {
  test("round-trips a spread of representative addresses", () => {
    const samples = [
      "0.0.0.0",
      "255.255.255.255",
      "192.168.1.1",
      "10.0.0.0",
      "172.16.254.1",
      "127.0.0.1",
      "8.8.8.8",
      "1.2.3.4",
    ];
    for (const ip of samples) {
      expect(intToIp(ipToInt(ip))).toBe(ip);
    }
  });

  test("ipToInt produces the expected 32-bit value", () => {
    // 192.168.1.1 = (192<<24)|(168<<16)|(1<<8)|1 = 3232235777
    expect(ipToInt("192.168.1.1")).toBe(3232235777);
    expect(ipToInt("0.0.0.0")).toBe(0);
    expect(ipToInt("255.255.255.255")).toBe(4294967295);
  });

  test("intToIp is the exact inverse for the boundary values", () => {
    expect(intToIp(0)).toBe("0.0.0.0");
    expect(intToIp(4294967295)).toBe("255.255.255.255");
  });

  test("adjacent integers produce adjacent-looking addresses (no sign issues from >>> 0)", () => {
    // Would previously break with plain >> due to sign extension on values >= 2^31.
    const highIp = "192.168.1.1"; // ipToInt > 2^31
    const asInt = ipToInt(highIp);
    expect(asInt).toBeGreaterThan(0);
    expect(intToIp(asInt)).toBe(highIp);
  });
});

describe("generateIPs", () => {
  test("/32 returns just the single address, not truncated", () => {
    const { ips, truncated } = generateIPs("10.0.0.5/32");
    expect(ips).toEqual(["10.0.0.5"]);
    expect(truncated).toBe(false);
  });

  test("/31 has no reserved network/broadcast: both addresses are usable", () => {
    const { ips, truncated } = generateIPs("10.0.0.0/31");
    expect(ips).toEqual(["10.0.0.0", "10.0.0.1"]);
    expect(truncated).toBe(false);
  });

  test("/30 excludes network and broadcast, leaving exactly 2 usable hosts", () => {
    const { ips, truncated } = generateIPs("192.168.1.0/30");
    // Block is .0 (network) .1 .2 (hosts) .3 (broadcast)
    expect(ips).toEqual(["192.168.1.1", "192.168.1.2"]);
    expect(truncated).toBe(false);
  });

  test("/24 excludes network (.0) and broadcast (.255), yielding 254 hosts", () => {
    const { ips, truncated } = generateIPs("192.168.1.0/24");
    expect(ips.length).toBe(254);
    expect(ips[0]).toBe("192.168.1.1");
    expect(ips[ips.length - 1]).toBe("192.168.1.254");
    expect(ips).not.toContain("192.168.1.0");
    expect(ips).not.toContain("192.168.1.255");
    expect(truncated).toBe(false);
  });

  test("/24 whose base address is not the network address still normalizes to the containing block", () => {
    const { ips } = generateIPs("192.168.1.130/24");
    expect(ips[0]).toBe("192.168.1.1");
    expect(ips[ips.length - 1]).toBe("192.168.1.254");
    expect(ips.length).toBe(254);
  });

  test("/16 truncates at MAX_HOSTS and reports truncated: true", () => {
    const { ips, truncated } = generateIPs("10.0.0.0/16");
    // /16 usable hosts = 65536 - 2 = 65534, far above MAX_HOSTS
    expect(truncated).toBe(true);
    expect(ips.length).toBe(MAX_HOSTS);
    expect(ips[0]).toBe("10.0.0.1");
    expect(ips).not.toContain("10.0.0.0");
    expect(ips).not.toContain("10.0.255.255");
  });

  test("/0 is capped at MAX_HOSTS and truncated", () => {
    const { ips, truncated } = generateIPs("0.0.0.0/0");
    expect(truncated).toBe(true);
    expect(ips.length).toBe(MAX_HOSTS);
  });

  test("a bare IP without a prefix is treated as a single host", () => {
    const { ips, truncated } = generateIPs("10.0.0.5");
    expect(ips).toEqual(["10.0.0.5"]);
    expect(truncated).toBe(false);
  });

  test("an invalid CIDR falls back to treating the base as a single target rather than throwing", () => {
    const { ips, truncated } = generateIPs("not-an-ip/24");
    expect(ips).toEqual(["not-an-ip"]);
    expect(truncated).toBe(false);
  });

  test("an out-of-range prefix falls back to a single target", () => {
    const { ips, truncated } = generateIPs("10.0.0.0/33");
    expect(ips).toEqual(["10.0.0.0"]);
    expect(truncated).toBe(false);
  });

  test("/29 yields 6 usable hosts excluding network and broadcast", () => {
    const { ips } = generateIPs("172.16.0.8/29");
    // Block: .8 network, .9-.14 hosts, .15 broadcast
    expect(ips).toEqual([
      "172.16.0.9",
      "172.16.0.10",
      "172.16.0.11",
      "172.16.0.12",
      "172.16.0.13",
      "172.16.0.14",
    ]);
  });
});
