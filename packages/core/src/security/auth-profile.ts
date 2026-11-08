import { and, eq } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../database/database"
import { AuthProfileTable } from "./sql"

export interface CreateAuthProfileInput {
  projectID: string
  roleName: string
  authType: "bearer" | "cookie" | "header" | "basic" | "oauth2"
  credentials: Record<string, string>
  preflightUrl?: string
}

export class AuthProfileService {
  /**
   * Registra o actualiza un perfil de autenticación con credenciales por rol (Etapa 3).
   */
  static saveProfile(db: Database.Interface["db"], input: CreateAuthProfileInput) {
    return Effect.gen(function* () {
      const now = Date.now()
      const existing = yield* db
        .select()
        .from(AuthProfileTable)
        .where(
          and(
            eq(AuthProfileTable.project_id, input.projectID),
            eq(AuthProfileTable.role_name, input.roleName),
          ),
        )
        .get()
        .pipe(Effect.orDie)

      if (existing) {
        yield* db
          .update(AuthProfileTable)
          .set({
            auth_type: input.authType,
            credentials: input.credentials,
            preflight_url: input.preflightUrl,
            time_updated: now,
          })
          .where(eq(AuthProfileTable.id, existing.id))
          .run()
          .pipe(Effect.orDie)

        return { id: existing.id, roleName: input.roleName, updated: true }
      }

      const id = `auth_${createHash("sha256").update(`${input.projectID}:${input.roleName}`).digest("hex").slice(0, 24)}`
      yield* db
        .insert(AuthProfileTable)
        .values({
          id,
          project_id: input.projectID,
          role_name: input.roleName,
          auth_type: input.authType,
          credentials: input.credentials,
          preflight_url: input.preflightUrl,
          preflight_status: "untested",
          time_created: now,
          time_updated: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { id, roleName: input.roleName, updated: false }
    })
  }

  /**
   * Genera las cabeceras HTTP correspondientes al perfil de autenticación.
   */
  static getAuthHeaders(profile: { auth_type: string; credentials: Record<string, string> }): Record<string, string> {
    const headers: Record<string, string> = {}
    switch (profile.auth_type) {
      case "bearer":
        if (profile.credentials.token) {
          headers["Authorization"] = `Bearer ${profile.credentials.token}`
        }
        break
      case "basic":
        if (profile.credentials.username && profile.credentials.password) {
          const auth = Buffer.from(`${profile.credentials.username}:${profile.credentials.password}`).toString("base64")
          headers["Authorization"] = `Basic ${auth}`
        }
        break
      case "cookie":
        if (profile.credentials.cookie) {
          headers["Cookie"] = profile.credentials.cookie
        }
        break
      case "header":
        if (profile.credentials.headerName && profile.credentials.headerValue) {
          headers[profile.credentials.headerName] = profile.credentials.headerValue
        }
        break
      case "oauth2":
        if (profile.credentials.accessToken) {
          headers["Authorization"] = `Bearer ${profile.credentials.accessToken}`
        }
        break
    }
    return headers
  }

  /**
   * Ejecuta una validación pre-flight contra la URL configurada.
   */
  static performPreflight(
    db: Database.Interface["db"],
    profileID: string,
    fetchFn?: (url: string, init?: RequestInit) => Promise<Response>,
  ) {
    return Effect.gen(function* () {
      const profile = yield* db
        .select()
        .from(AuthProfileTable)
        .where(eq(AuthProfileTable.id, profileID))
        .get()
        .pipe(Effect.orDie)

      if (!profile || !profile.preflight_url) {
        return { valid: false, reason: "No preflight URL configured" }
      }

      const headers = AuthProfileService.getAuthHeaders(profile)
      const doFetch = fetchFn ?? fetch
      const valid = yield* Effect.tryPromise({
        try: async () => {
          const res = await doFetch(profile.preflight_url!, {
            method: "GET",
            headers,
          })
          return res.status >= 200 && res.status < 400
        },
        catch: () => false,
      })

      const status = valid ? "valid" : "invalid"
      yield* db
        .update(AuthProfileTable)
        .set({
          preflight_status: status,
          last_preflight_at: Date.now(),
          time_updated: Date.now(),
        })
        .where(eq(AuthProfileTable.id, profileID))
        .run()
        .pipe(Effect.orDie)

      return { valid, status }
    })
  }

  /**
   * Lista todos los perfiles de autenticación del proyecto.
   */
  static listProfiles(db: Database.Interface["db"], projectID: string) {
    return db
      .select()
      .from(AuthProfileTable)
      .where(eq(AuthProfileTable.project_id, projectID))
      .all()
      .pipe(Effect.orDie)
  }
}
