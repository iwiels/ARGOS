import { describe, expect, test } from "bun:test"
import { mapFindingToAttack } from "@argos/core/threat-intel/attack"
import { extractIocs, domainFromUrl } from "@argos/core/threat-intel/iocs"

describe("mapFindingToAttack", () => {
  test("maps CWE-89 findings to T1190", () => {
    const matches = mapFindingToAttack({ cwe: "CWE-89", title: "SQL injection in login", tags: ["sqli"] })
    expect(matches.map((match) => match.id)).toContain("T1190")
  })

  test("maps XSS tags to T1190 and keeps reasons", () => {
    const matches = mapFindingToAttack({ title: "Reflected XSS", tags: ["xss"] })
    const xss = matches.find((match) => match.id === "T1190")
    expect(xss?.tactics).toContain("Initial Access")
    expect(xss?.reason).toContain("tag:xss")
  })

  test("maps port-scan tool evidence to T1046", () => {
    const matches = mapFindingToAttack({ sourceTool: "lan.port_scan", title: "Open ports on host" })
    expect(matches.map((match) => match.id)).toContain("T1046")
  })

  test("maps hardcoded credentials to T1552", () => {
    const matches = mapFindingToAttack({ title: "API key in .env", tags: ["hardcoded-secret"] })
    expect(matches.map((match) => match.id)).toContain("T1552")
  })

  test("caps at 5 techniques sorted by signal count", () => {
    const matches = mapFindingToAttack({
      cwe: "CWE-89",
      title: "SQL injection",
      tags: ["sqli", "rce"],
      sourceTool: "web.scan",
    })
    expect(matches.length).toBeLessThanOrEqual(5)
    expect(matches.length).toBeGreaterThan(0)
  })
})

describe("extractIocs", () => {
  test("extracts IPs, domains, hashes and emails", () => {
    const iocs = extractIocs(
      "Evidence: attacker from 203.0.113.7 hit evil.example.com (md5 44d88612fea8a8f36de82e1278abb02f, sha256 a" +
        "bc123456789012345678901234567890123456789012345678901234567890). Contact admin@evil.example.com",
    )
    const types = Object.fromEntries(iocs.map((ioc) => [ioc.type, ioc.value]))
    expect(types.ip).toBe("203.0.113.7")
    expect(types.domain).toBe("evil.example.com")
    expect(types.hash).toBe("44d88612fea8a8f36de82e1278abb02f")
    expect(types.email).toBe("admin@evil.example.com")
  })

  test("deduplicates repeated values and lowercases domains", () => {
    const iocs = extractIocs("CALL 203.0.113.7 and again 203.0.113.7 and Evil.Example.COM")
    expect(iocs.filter((ioc) => ioc.type === "ip")).toHaveLength(1)
    expect(iocs.filter((ioc) => ioc.type === "domain")[0]?.value).toBe("evil.example.com")
  })

  test("skips URL host duplicates as separate domains", () => {
    const iocs = extractIocs("Open redirect: https://evil.example.com/login?next=/admin")
    const urls = iocs.filter((ioc) => ioc.type === "url")
    const domains = iocs.filter((ioc) => ioc.type === "domain")
    expect(urls.length).toBeGreaterThan(0)
    // El host de la URL no debe aparecer también como dominio.
    expect(domains.some((ioc) => ioc.value === "evil.example.com")).toBe(false)
  })

  test("skips filenames and script extensions as domains", () => {
    const iocs = extractIocs("Files found: Registro.asp, AR500ESP.EXE, psalm.xml, index.php, config.json and real domain example.com")
    const domains = iocs.filter((ioc) => ioc.type === "domain").map((ioc) => ioc.value)
    expect(domains).toContain("example.com")
    expect(domains).not.toContain("registro.asp")
    expect(domains).not.toContain("ar500esp.exe")
    expect(domains).not.toContain("psalm.xml")
    expect(domains).not.toContain("index.php")
    expect(domains).not.toContain("config.json")
  })

  test("excludes the finding's own source_tool instead of reporting it as a domain", () => {
    // `.review` y `.osint` son TLD válidos, así que `code.review` y
    // `recon.osint` pasaban el filtro de dominio y cada hallazgo mostraba su
    // propia herramienta de origen como un IoC observado en el objetivo.
    const text = "source_tool: code.review — leak en https://cliente.example.com/repo"
    expect(extractIocs(text).some((ioc) => ioc.value === "code.review")).toBe(true)

    const filtered = extractIocs(text, { exclude: ["code.review"] })
    expect(filtered.some((ioc) => ioc.value === "code.review")).toBe(false)
    // El IoC real del objetivo sigue presente.
    expect(filtered.some((ioc) => ioc.value.includes("cliente.example.com"))).toBe(true)
  })

  test("ignores empty and nullish exclusions", () => {
    const iocs = extractIocs("dominio real example.com", { exclude: [undefined, null, "  "] })
    expect(iocs.some((ioc) => ioc.value === "example.com")).toBe(true)
  })

  test("domainFromUrl strips scheme and www", () => {
    expect(domainFromUrl("https://www.evil.example.com/x")).toBe("evil.example.com")
  })
})

describe("lookupIocReputation", () => {
  test("returns empty array when no API keys are provided", async () => {
    const { lookupIocReputation } = await import("@argos/core/threat-intel/reputation")
    const { Effect } = await import("effect")

    const results = await Effect.runPromise(
      lookupIocReputation({ type: "ip", value: "1.1.1.1" }, { timeoutMs: 100 }),
    )
    expect(results).toEqual([])
  })

  test("reads config gracefully from environment", async () => {
    const { reputationConfigFromEnv } = await import("@argos/core/threat-intel/reputation")
    const config = reputationConfigFromEnv()
    expect(typeof config).toBe("object")
  })
})

describe("ThreatIntelEnrichment", () => {
  test("enriches a finding in database with ATT&CK techniques and extracted IoCs", async () => {
    const { Database } = await import("@argos/core/database/database")
    const { FindingTable } = await import("@argos/core/security/sql")
    const { SessionV2 } = await import("@argos/core/session")
    const { layer } = await import("@argos/core/threat-intel/enrichment")
    const { Effect, Layer } = await import("effect")
    const { eq } = await import("drizzle-orm")

    const { Service } = await import("@argos/core/threat-intel/enrichment")

    const { Project } = await import("@argos/core/project")
    const { ProjectTable } = await import("@argos/core/project/sql")
    const { SessionTable } = await import("@argos/core/session/sql")
    const { AbsolutePath } = await import("@argos/core/schema")
    const { ingestToolPart } = await import("@argos/core/security/ingest")

    const program = Effect.gen(function* () {
      const { db } = yield* Database.Service
      const service = yield* Service

      const sessionID = SessionV2.ID.make("ses_enrich_test")

      // Seed Project and Session
      yield* db
        .insert(ProjectTable)
        .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(SessionTable)
        .values({
          id: sessionID,
          project_id: Project.ID.global,
          slug: "enrich-test",
          directory: "/project",
          title: "enrich test",
          version: "test",
        })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)

      // Ingest finding via ingestToolPart
      yield* ingestToolPart(db, {
        sessionID,
        type: "tool",
        tool: "argos_memory_save",
        state: {
          status: "completed",
          input: {
            kind: "finding",
            title: "SQL Injection in auth endpoint",
            severity: "CRÍTICO",
            cwe: "CWE-89",
            tags: ["sqli", "auth"],
            target: "http://example.com/login",
            vector: "http://example.com/login?user=admin",
            evidence: "Attacker sent payload from 198.51.100.44 to test.example.com",
            agent_assessment: "I verified the request reached the vulnerable query and changed its response.",
            impact: "An attacker can read records outside the intended account boundary.",
            source_tool: "web.scan",
          },
          output: "ok",
        },
      })

      const rows = yield* db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all()
        .pipe(Effect.orDie)

      expect(rows).toHaveLength(1)
      const findingID = rows[0].id

      // Ejecutar enrichment
      yield* service.enrich(findingID)

      // Verificar que el finding se actualizó con técnicas ATT&CK e IoCs
      const updated = yield* db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.id, findingID))
        .get()
        .pipe(Effect.orDie)

      expect(updated).toBeDefined()
      expect(updated!.attack_techniques).toBeDefined()
      expect(Array.isArray(updated!.attack_techniques)).toBe(true)
      expect(updated!.attack_techniques!.length).toBeGreaterThan(0)
      expect(updated!.attack_techniques!.some((t: any) => t.id === "T1190")).toBe(true)

      expect(updated!.iocs).toBeDefined()
      expect(Array.isArray(updated!.iocs)).toBe(true)
      expect(updated!.iocs!.some((ioc: any) => ioc.value === "198.51.100.44")).toBe(true)
      expect(updated!.enriched_at).toBeDefined()
    })

    const database = Database.layerFromPath(":memory:")
    const appLayer = Layer.mergeAll(database, layer.pipe(Layer.provide(database)))
    await Effect.runPromise(program.pipe(Effect.provide(appLayer)))
  })
})




