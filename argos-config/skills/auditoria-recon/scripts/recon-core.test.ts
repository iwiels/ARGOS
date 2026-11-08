import { describe, expect, test } from "bun:test";
import { dmarcQueryName, main, resolveSubdomains } from "./recon-core";

test("blocks live recon until it can use the isolated scope gateway", () => {
  expect(main()).toMatchObject({ status: "blocked", coverage: "not-run" });
});

describe("dmarcQueryName", () => {
  test("queries the _dmarc subdomain, never the apex domain", () => {
    expect(dmarcQueryName("example.com")).toBe("_dmarc.example.com");
  });

  test("does not accidentally query the apex TXT record (regression guard for the fixed bug)", () => {
    const target = "argos.com";
    expect(dmarcQueryName(target)).not.toBe(target);
    expect(dmarcQueryName(target)).toBe(`_dmarc.${target}`);
  });

  test("handles subdomains as targets correctly", () => {
    expect(dmarcQueryName("mail.example.com")).toBe("_dmarc.mail.example.com");
  });
});

describe("resolveSubdomains", () => {
  test("resolves each subdomain through the injected resolver and keeps only successes", async () => {
    const calls: string[] = [];
    const resolver = async (hostname: string) => {
      calls.push(hostname);
      if (hostname === "down.example.com") throw new Error("NXDOMAIN");
      return [`1.2.3.${calls.length}`];
    };

    const result = await resolveSubdomains(
      ["a.example.com", "down.example.com", "b.example.com"],
      resolver,
    );

    expect(calls.sort()).toEqual(["a.example.com", "b.example.com", "down.example.com"].sort());
    expect(result.map((r) => r.subdomain).sort()).toEqual(["a.example.com", "b.example.com"]);
    for (const entry of result) {
      expect(Array.isArray(entry.ips)).toBe(true);
      expect(entry.ips.length).toBeGreaterThan(0);
    }
  });

  test("returns an empty list when every lookup fails, without throwing", async () => {
    const resolver = async () => {
      throw new Error("ENOTFOUND");
    };
    const result = await resolveSubdomains(["a.example.com", "b.example.com"], resolver);
    expect(result).toEqual([]);
  });

  test("returns an empty list for an empty input without invoking the resolver", async () => {
    let invoked = false;
    const resolver = async (hostname: string) => {
      invoked = true;
      return [hostname];
    };
    const result = await resolveSubdomains([], resolver);
    expect(result).toEqual([]);
    expect(invoked).toBe(false);
  });

  test("batches resolution with bounded concurrency (never more than 20 in flight at once)", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const subdomains = Array.from({ length: 47 }, (_, i) => `sub${i}.example.com`);

    const resolver = async (hostname: string) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      // Yield to the event loop so concurrent calls actually overlap.
      await new Promise((r) => setTimeout(r, 1));
      inFlight--;
      return [`10.0.0.1`, hostname];
    };

    const result = await resolveSubdomains(subdomains, resolver);

    expect(result.length).toBe(47);
    expect(maxInFlight).toBeLessThanOrEqual(20);
    expect(maxInFlight).toBeGreaterThan(1); // confirms it does run in parallel, not sequentially
  });

  test("preserves the ips returned by the resolver for each subdomain", async () => {
    const resolver = async (hostname: string) => {
      if (hostname === "www.example.com") return ["93.184.216.34"];
      return ["10.0.0.1"];
    };
    const result = await resolveSubdomains(["www.example.com"], resolver);
    expect(result).toEqual([{ subdomain: "www.example.com", ips: ["93.184.216.34"] }]);
  });
});
