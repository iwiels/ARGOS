import { describe, expect, test } from "bun:test"
import { attackTechniqueName, mapFindingToAttack } from "./attack"

describe("mapFindingToAttack — catálogo base (regresión)", () => {
  test("SQLi por CWE mapea a T1190", () => {
    const matches = mapFindingToAttack({ cwe: "CWE-89", title: "SQL injection en /login" })
    expect(matches.some((m) => m.id === "T1190")).toBe(true)
  })
})

describe("mapFindingToAttack — técnicas añadidas para la biblioteca de skills", () => {
  test("Kerberoasting (tag) mapea a T1558.003", () => {
    const matches = mapFindingToAttack({
      title: "Cuenta de servicio con SPN vulnerable a Kerberoasting",
      tags: ["kerberoasting", "spn"],
    })
    expect(matches.some((m) => m.id === "T1558.003")).toBe(true)
    expect(attackTechniqueName("T1558.003")).toBe("Steal or Forge Kerberos Tickets: Kerberoasting")
  })

  test("NTLM relay (tag + CWE-300) mapea a T1557.001", () => {
    const matches = mapFindingToAttack({
      title: "SMB signing no requerido en host interno",
      cwe: "CWE-300",
      tags: ["ntlm-relay", "smb-signing"],
    })
    expect(matches.some((m) => m.id === "T1557.001")).toBe(true)
  })

  test("Container escape (privileged container) mapea a T1611", () => {
    const matches = mapFindingToAttack({
      title: "Contenedor corriendo en modo privilegiado",
      cwe: "CWE-250",
      tags: ["privileged-container", "container-escape"],
    })
    expect(matches.some((m) => m.id === "T1611")).toBe(true)
  })

  test("Cloud IAM overprivilege (wildcard policy) mapea a T1526", () => {
    const matches = mapFindingToAttack({
      title: "Policy IAM con Action:* y Resource:*",
      tags: ["wildcard-policy", "iam-overprivilege"],
    })
    expect(matches.some((m) => m.id === "T1526")).toBe(true)
  })

  test("Bucket S3 público mapea a T1530", () => {
    const matches = mapFindingToAttack({
      title: "Bucket S3 con listado público",
      cwe: "CWE-284",
      tags: ["public-bucket", "s3-exposure"],
    })
    expect(matches.some((m) => m.id === "T1530")).toBe(true)
  })

  test("Kubernetes cluster-admin binding mapea a T1610", () => {
    const matches = mapFindingToAttack({
      title: "ClusterRoleBinding otorga cluster-admin a ServiceAccount de aplicación",
      cwe: "CWE-269",
      tags: ["cluster-admin", "rbac"],
    })
    expect(matches.some((m) => m.id === "T1610")).toBe(true)
  })

  test("JWT alg:none mapea a T1078 (extendido)", () => {
    const matches = mapFindingToAttack({
      title: "El servidor acepta JWT con alg:none",
      cwe: "CWE-347",
      tags: ["jwt", "alg-none"],
    })
    expect(matches.some((m) => m.id === "T1078")).toBe(true)
  })

  test("BOLA/IDOR sigue mapeando a T1078 tras la extensión de tags", () => {
    const matches = mapFindingToAttack({
      title: "GET /api/orders/{id} devuelve pedidos de otros usuarios",
      cwe: "CWE-639",
      tags: ["bola", "idor"],
    })
    expect(matches.some((m) => m.id === "T1078")).toBe(true)
  })

  test("GraphQL introspection expuesta mapea a T1590 (nueva técnica de Reconnaissance)", () => {
    const matches = mapFindingToAttack({
      title: "Introspección GraphQL habilitada en producción",
      tags: ["graphql-introspection", "schema-disclosure"],
    })
    expect(matches.some((m) => m.id === "T1590")).toBe(true)
  })

  test("subdomain takeover (CNAME colgante) mapea a T1584.004 y T1583.001", () => {
    const matches = mapFindingToAttack({
      title: "CNAME apunta a un bucket S3 no reclamado",
      tags: ["subdomain-takeover", "dangling-cname"],
    })
    const ids = matches.map((m) => m.id)
    expect(ids).toContain("T1584.004")
    expect(ids).toContain("T1583.001")
  })

  test("DMARC p=none / SPF permisivo mapea a T1586.002 (BEC)", () => {
    const matches = mapFindingToAttack({
      title: "DMARC p=none permite suplantación de dominio",
      cwe: "CWE-290",
      tags: ["dmarc-none", "bec"],
    })
    expect(matches.some((m) => m.id === "T1586.002")).toBe(true)
  })

  test("harvesting de correos de empleados mapea a T1589.002", () => {
    const matches = mapFindingToAttack({
      title: "Superficie BEC: formato first.last@ y empleados públicos indexados",
      tags: ["email-harvesting", "bec-surface"],
    })
    expect(matches.some((m) => m.id === "T1589.002")).toBe(true)
  })

  test("shadow IT vía tokens en TXT mapea a T1592", () => {
    const matches = mapFindingToAttack({
      title: "Tokens de verificación SaaS huérfanos en registros TXT",
      tags: ["shadow-it", "saas-token-leak"],
    })
    expect(matches.some((m) => m.id === "T1592")).toBe(true)
  })
})

describe("mapFindingToAttack — no rompe el catálogo existente", () => {
  test("un hallazgo sin señal alguna devuelve lista vacía, no falla", () => {
    expect(mapFindingToAttack({ title: "Nota sin clasificar" })).toEqual([])
  })
})
