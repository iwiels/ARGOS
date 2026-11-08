export type SupportedLanguage = "typescript" | "javascript" | "go" | "python"

export interface RouteSymbol {
  language: SupportedLanguage
  filePath: string
  lineNumber: number
  method: string
  path: string
  handlerSymbol?: string
  framework: string
}

export interface ReachabilityResult {
  endpoint: string
  method: string
  matchedRoute?: RouteSymbol
  isReachable: boolean
  confidence: "exact" | "pattern" | "unmatched"
  sourceLocation?: {
    file: string
    line: number
    symbol?: string
  }
}

export class CodeReachabilityService {
  /**
   * Extrae declaraciones de rutas de archivos de código fuente en TypeScript/JavaScript, Go y Python (Etapa 5).
   */
  static extractRoutes(filePath: string, content: string): RouteSymbol[] {
    const routes: RouteSymbol[] = []
    const lines = content.split(/\r?\n/)

    const ext = filePath.split(".").pop()?.toLowerCase()
    let lang: SupportedLanguage | null = null

    if (ext === "ts" || ext === "tsx") lang = "typescript"
    else if (ext === "js" || ext === "jsx" || ext === "mjs") lang = "javascript"
    else if (ext === "go") lang = "go"
    else if (ext === "py") lang = "python"

    if (!lang) return []

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      const lineNum = i + 1

      // 1. TypeScript / JavaScript (Express, Fastify, Hono, NestJS)
      if (lang === "typescript" || lang === "javascript") {
        // app.get('/path', handler) / router.post('/path', handler)
        const expressMatch = line.match(/(?:app|router|server)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`](?:,\s*(\w+))?/i)
        if (expressMatch) {
          routes.push({
            language: lang,
            filePath,
            lineNumber: lineNum,
            method: expressMatch[1].toUpperCase(),
            path: expressMatch[2],
            handlerSymbol: expressMatch[3],
            framework: "express/fastify",
          })
          continue
        }

        // NestJS decorators: @Get('/path'), @Post('/path')
        const nestMatch = line.match(/@(Get|Post|Put|Delete|Patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/i)
        if (nestMatch) {
          // Extraer nombre del método decorado en la siguiente línea si es posible
          const nextLine = lines[i + 1] || ""
          const methodMatch = nextLine.match(/(?:async\s+)?(\w+)\s*\(/)
          routes.push({
            language: lang,
            filePath,
            lineNumber: lineNum,
            method: nestMatch[1].toUpperCase(),
            path: nestMatch[2],
            handlerSymbol: methodMatch ? methodMatch[1] : undefined,
            framework: "nestjs",
          })
          continue
        }
      }

      // 2. Go (Gin, Chi, Echo, net/http)
      if (lang === "go") {
        // r.GET("/path", handler) / r.POST("/path", handler)
        const ginMatch = line.match(/(?:\w+)\.(GET|POST|PUT|DELETE|PATCH|HandleFunc)\s*\(\s*"([^"]+)"(?:,\s*(\w+))?/i)
        if (ginMatch) {
          const method = ginMatch[1].toUpperCase() === "HANDLEFUNC" ? "ANY" : ginMatch[1].toUpperCase()
          routes.push({
            language: "go",
            filePath,
            lineNumber: lineNum,
            method,
            path: ginMatch[2],
            handlerSymbol: ginMatch[3],
            framework: "gin/net/http",
          })
          continue
        }
      }

      // 3. Python (FastAPI, Flask, Django)
      if (lang === "python") {
        // @app.get("/path") / @router.post("/path")
        const fastApiMatch = line.match(/@(?:\w+)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/i)
        if (fastApiMatch) {
          const nextLine = lines[i + 1] || ""
          const defMatch = nextLine.match(/def\s+(\w+)\s*\(/)
          routes.push({
            language: "python",
            filePath,
            lineNumber: lineNum,
            method: fastApiMatch[1].toUpperCase(),
            path: fastApiMatch[2],
            handlerSymbol: defMatch ? defMatch[1] : undefined,
            framework: "fastapi",
          })
          continue
        }

        // Flask: @app.route("/path", methods=["POST"])
        const flaskMatch = line.match(/@(?:\w+)\.route\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?/i)
        if (flaskMatch) {
          const rawMethods = flaskMatch[2] ? flaskMatch[2].replace(/['"\s]/g, "").toUpperCase() : "GET"
          const methods = rawMethods.split(",")
          const nextLine = lines[i + 1] || ""
          const defMatch = nextLine.match(/def\s+(\w+)\s*\(/)
          for (const m of methods) {
            routes.push({
              language: "python",
              filePath,
              lineNumber: lineNum,
              method: m,
              path: flaskMatch[1],
              handlerSymbol: defMatch ? defMatch[1] : undefined,
              framework: "flask",
            })
          }
          continue
        }
      }
    }

    return routes
  }

  /**
   * Correlaciona un endpoint auditado con su símbolo de código fuente.
   */
  static correlateEndpoint(
    endpointPath: string,
    method: string,
    availableRoutes: RouteSymbol[],
  ): ReachabilityResult {
    const cleanPath = endpointPath.split("?")[0].trim().toLowerCase()
    const targetMethod = method.toUpperCase()

    // 1. Coincidencia exacta de path y método
    const exact = availableRoutes.find(
      (r) => r.path.toLowerCase() === cleanPath && (r.method === targetMethod || r.method === "ANY"),
    )
    if (exact) {
      return {
        endpoint: endpointPath,
        method: targetMethod,
        matchedRoute: exact,
        isReachable: true,
        confidence: "exact",
        sourceLocation: {
          file: exact.filePath,
          line: exact.lineNumber,
          symbol: exact.handlerSymbol,
        },
      }
    }

    // 2. Coincidencia parametrizada (ej. /users/:id o /users/{id} vs /users/123)
    const patternMatch = availableRoutes.find((r) => {
      if (r.method !== targetMethod && r.method !== "ANY") return false
      // Normalizar :param y {param} a [^/]+
      const regexPattern = "^" + r.path.replace(/:[\w-]+/g, "[^/]+").replace(/\{[\w-]+\}/g, "[^/]+") + "$"
      return new RegExp(regexPattern, "i").test(cleanPath)
    })

    if (patternMatch) {
      return {
        endpoint: endpointPath,
        method: targetMethod,
        matchedRoute: patternMatch,
        isReachable: true,
        confidence: "pattern",
        sourceLocation: {
          file: patternMatch.filePath,
          line: patternMatch.lineNumber,
          symbol: patternMatch.handlerSymbol,
        },
      }
    }

    return {
      endpoint: endpointPath,
      method: targetMethod,
      isReachable: false,
      confidence: "unmatched",
    }
  }
}
