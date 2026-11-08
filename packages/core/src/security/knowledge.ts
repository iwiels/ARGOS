import { sql } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { FindingTable } from "./sql"

export interface KnowledgeEntry {
  sessionID: string
  projectID: string
  title: string
  cwe?: string
  target?: string
  content: string
}

export interface SearchResult {
  title: string
  cwe?: string
  target?: string
  snippet: string
  sessionID: string
}

export class KnowledgeBaseService {
  /**
   * Indexa un elemento en el índice FTS5 local (Etapa 4).
   */
  static index(db: Database.Interface["db"], entry: KnowledgeEntry) {
    return Effect.gen(function* () {
      yield* db
        .run(
          sql`INSERT INTO security_knowledge_fts(session_id, project_id, title, cwe, target, content)
              VALUES (${entry.sessionID}, ${entry.projectID}, ${entry.title}, ${entry.cwe || ""}, ${entry.target || ""}, ${entry.content})`,
        )
        .pipe(
          Effect.catch(() => Effect.void), // En caso de que FTS5 esté deshabilitado en algún entorno
        )
    })
  }

  /**
   * Indexa en bloque todos los hallazgos de una sesión.
   */
  static indexSessionFindings(db: Database.Interface["db"], sessionID: string) {
    return Effect.gen(function* () {
      const findings = yield* db
        .select()
        .from(FindingTable)
        .where(sql`${FindingTable.session_id} = ${sessionID}`)
        .all()
        .pipe(Effect.orDie)

      for (const f of findings) {
        const content = [
          f.title,
          f.cwe,
          f.target,
          f.vector,
          f.remediation,
          typeof f.evidence === "object" ? JSON.stringify(f.evidence) : String(f.evidence),
        ]
          .filter(Boolean)
          .join(" ")

        yield* KnowledgeBaseService.index(db, {
          sessionID: f.session_id,
          projectID: f.project_id,
          title: f.title,
          cwe: f.cwe ?? undefined,
          target: f.target ?? undefined,
          content,
        })
      }

      return { indexedCount: findings.length }
    })
  }

  /**
   * Realiza una búsqueda FTS5 con snippets.
   */
  static search(db: Database.Interface["db"], query: string, limit = 10) {
    return Effect.gen(function* () {
      const cleanQuery = query.replace(/[^\w\s-]/g, "").trim()
      if (!cleanQuery) return []

      const formattedQuery = cleanQuery
        .split(/\s+/)
        .map((term) => `"${term}"*`)
        .join(" OR ")

      const results = yield* db
        .all<{
          session_id: string
          project_id: string
          title: string
          cwe: string
          target: string
          content: string
        }>(
          sql`SELECT session_id, project_id, title, cwe, target, content
              FROM security_knowledge_fts
              WHERE security_knowledge_fts MATCH ${formattedQuery}
              LIMIT ${limit}`,
        )
        .pipe(
          Effect.catch(() => Effect.succeed([])),
        )

      return results.map((r) => ({
        sessionID: r.session_id,
        projectID: r.project_id,
        title: r.title,
        cwe: r.cwe,
        target: r.target,
        snippet: r.content.slice(0, 200),
      }))
    })
  }
}
