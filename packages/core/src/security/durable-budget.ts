import { eq } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../database/database"
import { AuditDurableBudgetTable } from "./sql"

export interface ModelPricing {
  inputPerMillion: number
  outputPerMillion: number
}

export const DEFAULT_MODEL_PRICING: Record<string, ModelPricing> = {
  "claude-3-5-sonnet": { inputPerMillion: 3.0, outputPerMillion: 15.0 },
  "gpt-4o": { inputPerMillion: 2.5, outputPerMillion: 10.0 },
  "gpt-4o-mini": { inputPerMillion: 0.15, outputPerMillion: 0.6 },
  default: { inputPerMillion: 3.0, outputPerMillion: 15.0 },
}

export interface RecordUsageInput {
  sessionID: string
  projectID: string
  model?: string
  inputTokens?: number
  outputTokens?: number
  toolCalls?: number
  externalApiCalls?: number
}

export interface BudgetLimits {
  maxCostUsd?: number
  maxTokens?: number
  maxTurns?: number
  maxToolCalls?: number
}

export class DurableBudgetService {
  /**
   * Calcula el costo en USD según los tokens de entrada y salida y el modelo.
   */
  static calculateCostUsd(model: string = "default", inputTokens: number = 0, outputTokens: number = 0): number {
    const key = Object.keys(DEFAULT_MODEL_PRICING).find((k) => model.toLowerCase().includes(k)) ?? "default"
    const pricing = DEFAULT_MODEL_PRICING[key]
    const inputCost = (inputTokens / 1_000_000) * pricing.inputPerMillion
    const outputCost = (outputTokens / 1_000_000) * pricing.outputPerMillion
    return inputCost + outputCost
  }

  /**
   * Acumula el uso duradero de tokens, llamadas a tools y costo en la base de datos (Etapa 3).
   */
  static recordUsage(db: Database.Interface["db"], input: RecordUsageInput) {
    return Effect.gen(function* () {
      const now = Date.now()
      const existing = yield* db
        .select()
        .from(AuditDurableBudgetTable)
        .where(eq(AuditDurableBudgetTable.session_id, input.sessionID))
        .get()
        .pipe(Effect.orDie)

      const costIncrement = DurableBudgetService.calculateCostUsd(
        input.model,
        input.inputTokens ?? 0,
        input.outputTokens ?? 0,
      )

      if (!existing) {
        const id = `bud_${createHash("sha256").update(`${input.sessionID}:${now}`).digest("hex").slice(0, 24)}`
        yield* db
          .insert(AuditDurableBudgetTable)
          .values({
            id,
            session_id: input.sessionID,
            project_id: input.projectID,
            turns_count: 1,
            tokens_input: input.inputTokens ?? 0,
            tokens_output: input.outputTokens ?? 0,
            total_cost_usd: costIncrement.toFixed(4),
            external_api_calls: input.externalApiCalls ?? 0,
            tool_calls: input.toolCalls ?? 0,
            time_updated: now,
          })
          .run()
          .pipe(Effect.orDie)

        return {
          sessionID: input.sessionID,
          turnsCount: 1,
          tokensInput: input.inputTokens ?? 0,
          tokensOutput: input.outputTokens ?? 0,
          totalCostUsd: costIncrement,
        }
      } else {
        const currentCost = parseFloat(existing.total_cost_usd || "0")
        const newCost = (currentCost + costIncrement).toFixed(4)
        const updatedTurns = existing.turns_count + 1
        const updatedInputTokens = existing.tokens_input + (input.inputTokens ?? 0)
        const updatedOutputTokens = existing.tokens_output + (input.outputTokens ?? 0)
        const updatedApiCalls = existing.external_api_calls + (input.externalApiCalls ?? 0)
        const updatedToolCalls = existing.tool_calls + (input.toolCalls ?? 0)

        yield* db
          .update(AuditDurableBudgetTable)
          .set({
            turns_count: updatedTurns,
            tokens_input: updatedInputTokens,
            tokens_output: updatedOutputTokens,
            total_cost_usd: newCost,
            external_api_calls: updatedApiCalls,
            tool_calls: updatedToolCalls,
            time_updated: now,
          })
          .where(eq(AuditDurableBudgetTable.session_id, input.sessionID))
          .run()
          .pipe(Effect.orDie)

        return {
          sessionID: input.sessionID,
          turnsCount: updatedTurns,
          tokensInput: updatedInputTokens,
          tokensOutput: updatedOutputTokens,
          totalCostUsd: parseFloat(newCost),
        }
      }
    })
  }

  /**
   * Obtiene el acumulado de uso de la sesión.
   */
  static getUsage(db: Database.Interface["db"], sessionID: string) {
    return Effect.gen(function* () {
      const budget = yield* db
        .select()
        .from(AuditDurableBudgetTable)
        .where(eq(AuditDurableBudgetTable.session_id, sessionID))
        .get()
        .pipe(Effect.orDie)

      if (!budget) {
        return {
          sessionID,
          turnsCount: 0,
          tokensInput: 0,
          tokensOutput: 0,
          totalCostUsd: 0,
          externalApiCalls: 0,
          toolCalls: 0,
        }
      }

      return {
        sessionID: budget.session_id,
        turnsCount: budget.turns_count,
        tokensInput: budget.tokens_input,
        tokensOutput: budget.tokens_output,
        totalCostUsd: parseFloat(budget.total_cost_usd),
        externalApiCalls: budget.external_api_calls,
        toolCalls: budget.tool_calls,
      }
    })
  }

  /**
   * Valida si el consumo actual excede los techos duros configurados.
   */
  static assertWithinLimits(db: Database.Interface["db"], sessionID: string, limits: BudgetLimits) {
    return Effect.gen(function* () {
      const usage = yield* DurableBudgetService.getUsage(db, sessionID)

      if (limits.maxCostUsd !== undefined && usage.totalCostUsd >= limits.maxCostUsd) {
        return yield* Effect.fail(
          new Error(`Presupuesto excedido: Costo $${usage.totalCostUsd.toFixed(2)} excede el límite de $${limits.maxCostUsd.toFixed(2)}`),
        )
      }
      const totalTokens = usage.tokensInput + usage.tokensOutput
      if (limits.maxTokens !== undefined && totalTokens >= limits.maxTokens) {
        return yield* Effect.fail(
          new Error(`Presupuesto excedido: Tokens ${totalTokens} exceden el límite de ${limits.maxTokens}`),
        )
      }
      if (limits.maxTurns !== undefined && usage.turnsCount >= limits.maxTurns) {
        return yield* Effect.fail(
          new Error(`Presupuesto excedido: Turnos ${usage.turnsCount} exceden el límite de ${limits.maxTurns}`),
        )
      }
      if (limits.maxToolCalls !== undefined && usage.toolCalls >= limits.maxToolCalls) {
        return yield* Effect.fail(
          new Error(`Presupuesto excedido: Tool calls ${usage.toolCalls} exceden el límite de ${limits.maxToolCalls}`),
        )
      }

      return usage
    })
  }
}
