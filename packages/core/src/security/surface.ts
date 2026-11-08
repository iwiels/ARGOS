export interface NormalizedParameter {
  name: string
  in: "query" | "path" | "header" | "body" | "cookie"
  required: boolean
  type?: string
  schema?: Record<string, unknown>
}

export interface NormalizedEndpoint {
  method: string
  path: string
  summary?: string
  operationId?: string
  parameters: NormalizedParameter[]
  requestBody?: {
    contentType: string
    schema?: Record<string, unknown>
  }
  authRequired: boolean
  securityRoles: string[]
  tags: string[]
}

export class SurfaceNormalizer {
  /**
   * Normaliza una especificación OpenAPI 3.x, Swagger 2.0 o Colección Postman v2.x (Etapa 3).
   */
  static normalize(spec: unknown): NormalizedEndpoint[] {
    if (!spec || typeof spec !== "object") return []

    const obj = spec as Record<string, any>

    // 1. Detectar OpenAPI 3.x o Swagger 2.0
    if (obj.openapi || obj.swagger) {
      return SurfaceNormalizer.normalizeOpenApi(obj)
    }

    // 2. Detectar Postman Collection
    if (obj.info && (obj.item || obj.info._postman_id || (obj.info.schema && obj.info.schema.includes("postman")))) {
      return SurfaceNormalizer.normalizePostman(obj)
    }

    return []
  }

  private static normalizeOpenApi(spec: Record<string, any>): NormalizedEndpoint[] {
    const endpoints: NormalizedEndpoint[] = []
    const paths = spec.paths || {}
    const globalSecurity = spec.security || []

    const HTTP_METHODS = ["get", "post", "put", "delete", "patch", "head", "options"]

    for (const [pathStr, pathItem] of Object.entries(paths)) {
      if (!pathItem || typeof pathItem !== "object") continue
      const commonParameters = (pathItem as any).parameters || []

      for (const method of HTTP_METHODS) {
        const op: any = (pathItem as any)[method]
        if (!op || typeof op !== "object") continue

        const opSecurity = op.security !== undefined ? op.security : globalSecurity
        const authRequired = Array.isArray(opSecurity) && opSecurity.length > 0
        const securityRoles: string[] = []

        if (Array.isArray(opSecurity)) {
          for (const secRequirement of opSecurity) {
            for (const [secName, scopes] of Object.entries(secRequirement)) {
              if (Array.isArray(scopes) && scopes.length > 0) {
                securityRoles.push(...scopes)
              } else {
                securityRoles.push(secName)
              }
            }
          }
        }

        const rawParams = [...commonParameters, ...(op.parameters || [])]
        const parameters: NormalizedParameter[] = rawParams.map((p: any) => ({
          name: p.name || "",
          in: p.in || "query",
          required: Boolean(p.required || p.in === "path"),
          type: p.schema?.type || p.type || "string",
          schema: p.schema,
        }))

        let requestBody: NormalizedEndpoint["requestBody"] = undefined
        if (op.requestBody?.content) {
          const firstContentType = Object.keys(op.requestBody.content)[0] || "application/json"
          requestBody = {
            contentType: firstContentType,
            schema: op.requestBody.content[firstContentType]?.schema,
          }
        }

        endpoints.push({
          method: method.toUpperCase(),
          path: pathStr,
          summary: op.summary || op.description,
          operationId: op.operationId,
          parameters,
          requestBody,
          authRequired,
          securityRoles: [...new Set(securityRoles)],
          tags: Array.isArray(op.tags) ? op.tags : [],
        })
      }
    }

    return endpoints
  }

  private static normalizePostman(spec: Record<string, any>): NormalizedEndpoint[] {
    const endpoints: NormalizedEndpoint[] = []

    function walkItems(items: any[]) {
      for (const item of items) {
        if (!item || typeof item !== "object") continue

        if (Array.isArray(item.item)) {
          walkItems(item.item)
          continue
        }

        const req = item.request
        if (!req) continue

        const method = (typeof req === "string" ? "GET" : req.method || "GET").toUpperCase()

        let rawPath = ""
        const queryParams: NormalizedParameter[] = []

        if (typeof req === "string") {
          rawPath = req
        } else if (typeof req.url === "string") {
          rawPath = req.url
        } else if (req.url && typeof req.url === "object") {
          if (Array.isArray(req.url.path)) {
            rawPath = "/" + req.url.path.join("/")
          } else {
            rawPath = req.url.raw || "/"
          }
          if (Array.isArray(req.url.query)) {
            for (const q of req.url.query) {
              if (q.key) {
                queryParams.push({
                  name: q.key,
                  in: "query",
                  required: false,
                  type: "string",
                })
              }
            }
          }
        }

        const authRequired = Boolean(req.auth && req.auth.type && req.auth.type !== "noauth")
        const securityRoles: string[] = authRequired ? [req.auth.type] : []

        endpoints.push({
          method,
          path: rawPath,
          summary: item.name || req.description,
          parameters: queryParams,
          authRequired,
          securityRoles,
          tags: [],
        })
      }
    }

    if (Array.isArray(spec.item)) {
      walkItems(spec.item)
    }

    return endpoints
  }
}
