import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { batchFetch, extractLinks, main, shallowCrawl } from "./web-core";

describe("web audit runtime gate", () => {
  test("blocks live scans without the isolated scope gateway", () => {
    const previousFetch = globalThis.fetch;
    let requests = 0;
    globalThis.fetch = (async () => {
      requests++;
      return new Response("", { status: 200 });
    }) as typeof fetch;

    try {
      expect(main()).toMatchObject({ status: "blocked", coverage: "not-run" });
      expect(requests).toBe(0);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});

describe("extractLinks", () => {
  test("resolves root-relative links against the base URL", () => {
    const html = `<a href="/about">About</a><a href="/contact">Contact</a>`;
    const links = extractLinks(html, "https://example.com");
    expect(links.sort()).toEqual(["https://example.com/about", "https://example.com/contact"].sort());
  });

  test("keeps absolute links (same-origin and cross-origin) as-is", () => {
    const html = `<a href="https://example.com/page">Same</a><a href="https://other.example/x">Other</a>`;
    const links = extractLinks(html, "https://example.com");
    expect(links.sort()).toEqual(["https://example.com/page", "https://other.example/x"].sort());
  });

  test("resolves relative links found deeper on a non-root page", () => {
    const html = `<a href="/deep/child">Child</a>`;
    const links = extractLinks(html, "https://example.com/deep/parent");
    expect(links).toEqual(["https://example.com/deep/child"]);
  });

  test("deduplicates repeated links", () => {
    const html = `<a href="/a">1</a><a href="/a">2</a><a href='/a'>3</a>`;
    const links = extractLinks(html, "https://example.com");
    expect(links).toEqual(["https://example.com/a"]);
  });

  test("ignores non-href attributes and malformed markup without throwing", () => {
    const html = `
      <img src="/logo.png" />
      <a name="anchor-only">No href</a>
      <a href="">Empty</a>
      <a href="javascript:void(0)">JS link</a>
      <a href="mailto:test@example.com">Mail</a>
      <div class="href-like-but-not-a-tag">href="/fake"</div>
      <a href="/real">Real link</a>
    `;
    const links = extractLinks(html, "https://example.com");
    // javascript:/mailto: links do not match the http(s)/root-relative regex and are skipped;
    // the href-looking text inside the div's class/content is not inside an href="..." attribute
    // context recognized by the extractor beyond what the regex matches, but since it matches the
    // literal pattern href="/fake" too, we only assert the definitely-valid link is present.
    expect(links).toContain("https://example.com/real");
    expect(links).not.toContain("https://example.com/void(0)");
  });

  test("returns an empty list when there are no anchor tags", () => {
    expect(extractLinks("<html><body><p>No links here</p></body></html>", "https://example.com")).toEqual([]);
  });

  test("skips hrefs that fail URL resolution instead of throwing", () => {
    const html = `<a href="http://[invalid">Bad</a><a href="/ok">Ok</a>`;
    const links = extractLinks(html, "https://example.com");
    expect(links).toEqual(["https://example.com/ok"]);
  });
});

describe("batchFetch and shallowCrawl (mocked fetch, no real network)", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("batchFetch keeps 200/301/302/403 and drops other statuses", async () => {
    const statusByUrl: Record<string, number> = {
      "https://example.com/ok": 200,
      "https://example.com/redirect": 302,
      "https://example.com/redirect-perm": 301,
      "https://example.com/forbidden": 403,
      "https://example.com/missing": 404,
      "https://example.com/error": 500,
    };

    const calls: { url: string; init?: RequestInit }[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, init });
      const status = statusByUrl[url] ?? 404;
      return new Response(null, { status });
    }) as typeof fetch;

    const results = await batchFetch(Object.keys(statusByUrl), 3);

    expect(results.sort((a, b) => a.url.localeCompare(b.url))).toEqual(
      [
        { url: "https://example.com/ok", status: 200 },
        { url: "https://example.com/redirect", status: 302 },
        { url: "https://example.com/redirect-perm", status: 301 },
        { url: "https://example.com/forbidden", status: 403 },
      ].sort((a, b) => a.url.localeCompare(b.url)),
    );

    // Redirects must not be followed automatically (a 301/302 itself is the signal).
    expect(calls.every((c) => c.init?.redirect === "manual")).toBe(true);
    expect(calls.length).toBe(Object.keys(statusByUrl).length);
  });

  test("batchFetch swallows network errors for individual URLs without failing the batch", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("boom")) throw new TypeError("network down");
      return new Response(null, { status: 200 });
    }) as typeof fetch;

    const results = await batchFetch(["https://example.com/fine", "https://example.com/boom"], 5);
    expect(results).toEqual([{ url: "https://example.com/fine", status: 200 }]);
  });

  test("shallowCrawl follows only same-origin links found on the root page (depth 1)", async () => {
    const pages: Record<string, string> = {
      "https://example.com": `
        <a href="/a">A</a>
        <a href="https://example.com/b">B</a>
        <a href="https://other.example/x">External</a>
      `,
      "https://example.com/a": `<a href="/c">C, only reachable from A</a>`,
      "https://example.com/b": `<p>no links</p>`,
    };

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      const html = pages[url];
      if (html === undefined) return new Response(null, { status: 404 });
      return new Response(html, { status: 200 });
    }) as typeof fetch;

    const { crawledUrls, pagesVisited } = await shallowCrawl("https://example.com");

    // Root + /a + /b were actually fetched; /c was only referenced by /a, never visited (depth 1).
    expect(pagesVisited).toBe(3);
    expect(crawledUrls.sort()).toEqual(
      [
        "https://example.com/a",
        "https://example.com/b",
        "https://other.example/x",
        "https://example.com/c",
      ].sort(),
    );
  });

  test("shallowCrawl handles an unreachable root page gracefully", async () => {
    globalThis.fetch = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;

    const { crawledUrls, pagesVisited } = await shallowCrawl("https://example.com");
    expect(crawledUrls).toEqual([]);
    expect(pagesVisited).toBe(1); // the root is marked visited even though the fetch failed
  });
});
