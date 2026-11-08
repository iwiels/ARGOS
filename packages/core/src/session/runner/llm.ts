import {
  LLM,
  LLMClient,
  LLMError,
  LLMEvent,
  SystemPart,
  isContextOverflowFailure,
  type ProviderErrorEvent,
  type Usage,
} from "@argos/llm"
import { Cause, DateTime, Effect, Exit, FiberSet, Layer, Option, Schema, Semaphore, Stream } from "effect"
import { AgentV2 } from "../../agent"
import { Config } from "../../config"
import { Database } from "../../database/database"
import { EventV2 } from "../../event"
import { Location } from "../../location"
import { ModelV2 } from "../../model"
import { ProviderV2 } from "../../provider"
import { QuestionV2 } from "../../question"
import { SystemContext } from "../../system-context/index"
import { SystemContextRegistry } from "../../system-context/registry"
import { SkillGuidance } from "../../skill/guidance"
import { ToolRegistry } from "../../tool/registry"
import { ToolOutputStore } from "../../tool-output-store"
import { SessionContextEpoch } from "../context-epoch"
import { SessionCompaction } from "../compaction"
import { SessionEvent } from "../event"
import { SessionHistory } from "../history"
import { SessionInput } from "../input"
import { SessionSchema } from "../schema"
import { SessionRunJournal } from "../run-journal"
import { SessionStore } from "../store"
import { EngagementBudget } from "../budget"
import { type RunError, Service, StepLimitExceededError } from "./index"
import { SessionRunnerModel } from "./model"
import { createLLMEventPublisher } from "./publish-llm-event"
import { toLLMMessages } from "./to-llm-message"
import { EngagementContext } from "../../security/pseudonymize"

/**
 * Runs one durable coding-agent Session until it settles.
 *
 * Keep this as orchestration over smaller collaborators rather than rebuilding the legacy
 * `SessionPrompt` monolith. Implement the unchecked items in small reviewed slices:
 *
 * - Session ownership and controls
 *   - [x] Coordinate one local active drain per Session; explicit resumes join and prompt wakeups coalesce.
 *   - [ ] Replace local ownership with durable multi-node ownership when clustered.
 *   - [ ] Mark busy, retrying, idle, interrupted, or terminal-failure status durably.
 *   - [ ] Honor interruption and reject stale work after runtime attachment replacement.
 *   - [x] Bound model steps.
 *   - [ ] Bound provider retries and repeated identical tool calls.
 *
 * - Runtime context assembly
 *   - Track V1 runtime-context parity canonically in `specs/v2/session.md`.
 *
 * - One provider turn
 *   - [x] Translate every projected V2 Session message variant into canonical
 *     `@argos/llm` messages.
 *   - [ ] Resolve policy-filtered built-in, MCP, plugin, and structured-output tool definitions.
 *   - [x] Stream exactly one `llm.stream(request)` provider turn.
 *   - [x] Persist assistant text and usage events incrementally as they arrive.
 *   - [ ] Persist snapshots, patches, and retry notices incrementally as they arrive.
 *   - [x] Persist reasoning, provider errors, and tool-call events incrementally as they arrive.
 *
 * - Tool settlement and continuation
 *   - [x] Durably record each tool call before side effects begin.
 *   - [x] Authorize and execute recorded local calls through a core-owned registry hook.
 *   - [x] Persist typed success, failure, and provider-executed tool outcomes.
 *   - [x] Start each recorded local call eagerly and await all settlements before continuation.
 *   - [ ] Add scoped runtime context, progress updates, attachment normalization,
 *     plugins, and cancellation settlement.
 *   - [x] Reload projected history and start the next explicit provider turn after local tool results.
 *   - [x] Continue for durable user steering accepted during an active provider turn.
 *   - [ ] Continue for compaction or another continuation condition when required.
 *
 * - Post-run maintenance
 *   - [ ] Settle final status and expose durable output events to replayable consumers.
 *   - [ ] Coalesce streamed deltas and add covering projected-history indexes.
 *   - [ ] Update title, summaries, compaction state, and cleanup in bounded background work.
 *
 * Use `llm.stream(request)` for each provider turn. Keep tool execution and continuation here.
 * Durable activity recovery remains a separate future slice with an explicit retry policy.
 *
 * The current slice loads V2 history, translates it, resolves a model through a core service, and persists one
 * provider turn. Registry definitions are advertised, local tool calls are settled durably, and a
 * bounded explicit loop starts the next provider turn after local settlement.
 */

// QUESTION: Did this exist previously, or did we add this limit? Does it make sense?
const MAX_STEPS = 25

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const events = yield* EventV2.Service
    const llm = yield* LLMClient.Service
    const agents = yield* AgentV2.Service
    const tools = yield* ToolRegistry.Service
    const models = yield* SessionRunnerModel.Service
    const store = yield* SessionStore.Service
    const location = yield* Location.Service
    const systemContext = yield* SystemContextRegistry.Service
    const skillGuidance = yield* SkillGuidance.Service
    const config = yield* Config.Service
    const budget = yield* EngagementBudget.Service
    const db = (yield* Database.Service).db
    const runJournal = SessionRunJournal.make(db)
    yield* runJournal.recoverAbandoned()
    const compaction = SessionCompaction.make({ events, llm, config: yield* config.entries() })
    const getSession = Effect.fn("SessionRunner.getSession")(function* (sessionID: SessionSchema.ID) {
      const session = yield* store.get(sessionID)
      if (!session) return yield* Effect.die(`Session not found: ${sessionID}`)
      return session
    })

    const getContext = Effect.fn("SessionRunner.getContext")(function* (sessionID: SessionSchema.ID) {
      return yield* store.context(sessionID)
    })
    const failInterruptedTools = Effect.fn("SessionRunner.failInterruptedTools")(function* (
      sessionID: SessionSchema.ID,
    ) {
      for (const message of yield* getContext(sessionID)) {
        if (message.type !== "assistant") continue
        for (const tool of message.content) {
          if (tool.type !== "tool" || (tool.state.status !== "pending" && tool.state.status !== "running")) continue
          yield* events.publish(SessionEvent.Tool.Failed, {
            sessionID,
            timestamp: yield* DateTime.now,
            assistantMessageID: message.id,
            callID: tool.id,
            error: { type: "unknown", message: "Tool execution interrupted" },
            provider: {
              executed: tool.provider?.executed === true,
              ...(tool.provider?.metadata === undefined ? {} : { metadata: tool.provider.metadata }),
            },
          })
        }
      }
    })

    const awaitToolFibers = (
      fibers: FiberSet.FiberSet<void, ToolOutputStore.Error | EngagementBudget.BudgetExceededError>,
    ) => Effect.raceFirst(FiberSet.join(fibers), FiberSet.awaitEmpty(fibers))

    // Match V1: dismissing a question halts the loop instead of becoming model-facing tool output.
    const isQuestionRejected = (cause: Cause.Cause<unknown>) =>
      cause.reasons.some((reason) => Cause.isDieReason(reason) && reason.defect instanceof QuestionV2.RejectedError)

    type TurnTransition =
      // Request preparation observed a concurrent Session change and must restart from durable state.
      | { readonly _tag: "RebuildPreparedTurn"; readonly promotion?: SessionInput.Delivery }
      // Overflow compaction completed; rebuild once through the path without overflow recovery.
      | { readonly _tag: "ContinueAfterOverflowCompaction" }

    class TurnTransitionError extends Error {
      constructor(readonly transition: TurnTransition) {
        super()
      }
    }

    const rebuildPreparedTurn = (promotion?: SessionInput.Delivery) =>
      new TurnTransitionError({ _tag: "RebuildPreparedTurn", promotion })
    const continueAfterOverflowCompaction = new TurnTransitionError({
      _tag: "ContinueAfterOverflowCompaction",
    })

    const retryAgentMismatch = (promotion: SessionInput.Delivery | undefined) =>
      Effect.catchDefect((defect) =>
        defect instanceof SessionContextEpoch.AgentMismatch
          ? Effect.die(rebuildPreparedTurn(promotion))
          : Effect.die(defect),
      )

    // Sin esto el modelo no tiene forma de saber su propio Session ID real —
    // los agentes en equipo (security-scout, security-web, …) corren fuera del
    // tracking de esta Session (ver argos-config/AGENTS.md) y solo pueden
    // devolver hallazgos reconciliables si el orquestador les pasa este ID
    // explícitamente en cada argos_memory_save / audit.run.start. Se
    // limita a agentes del equipo de seguridad (id con prefijo "security-",
    // ver argos-config/agent/security-*.md) para no inflar el prompt de
    // sesiones normales de coding con texto que nunca van a usar.
    const sessionIdContext = (sessionID: SessionSchema.ID, scope?: SessionSchema.Info["scope"]) =>
      SystemContext.make({
        key: SystemContext.Key.make("core/argos-session-id"),
        codec: Schema.toCodecJson(Schema.String),
        load: Effect.succeed<string>(sessionID),
        baseline: (id) => {
          const scopeDomains = scope?.domains ?? []
          const scopeCidrs = scope?.cidrs ?? []
          const hasScope = scopeDomains.length > 0 || scopeCidrs.length > 0
          return [
            `Your Argos session ID is: ${id}`,
            `When delegating to peer agents or calling argos_memory_save / audit.run.start yourself, pass this exact value as "argos_session_id" so findings can be reconciled back into this session.`,
            ...(hasScope
              ? [
                  `Authorized Scope (configured by operator):`,
                  ...(scopeDomains.length > 0 ? [`- Allowed Domains: ${scopeDomains.join(", ")}`] : []),
                  ...(scopeCidrs.length > 0 ? [`- Allowed CIDRs: ${scopeCidrs.join(", ")}`] : []),
                  `Targets within this scope or requested by the operator are PRE-AUTHORIZED. Do NOT stop or ask for authorization confirmation. Pass authorized: true to argos_audit_run_start.`,
                ]
              : [
                  `When the operator requests an audit for a specific target (via command or prompt), that target is PRE-AUTHORIZED by the operator. Pass authorized: true to argos_audit_run_start and do not pause to ask redundant authorization confirmation.`,
                ]),
          ].join("\n")
        },
        update: (_previous, id) => `Your Argos session ID is now: ${id}`,
      })
    const isSecurityTeamAgent = (agentID: AgentV2.ID) => agentID.startsWith("security-")

    const sameModel = Schema.toEquivalence(Schema.UndefinedOr(ModelV2.Ref))
    const loadSystemContext = (agent: AgentV2.Selection, sessionID: SessionSchema.ID, scope?: SessionSchema.Info["scope"]) =>
      isSecurityTeamAgent(agent.id)
        ? Effect.all(
            [systemContext.load(), skillGuidance.load(agent), Effect.succeed(sessionIdContext(sessionID, scope))],
            { concurrency: "unbounded" },
          ).pipe(Effect.map(SystemContext.combine))
        : Effect.all([systemContext.load(), skillGuidance.load(agent)], { concurrency: "unbounded" }).pipe(
            Effect.map(SystemContext.combine),
          )

    const runTurnAttempt = Effect.fn("SessionRunner.runTurn")(function* (
      sessionID: SessionSchema.ID,
      promotion: SessionInput.Delivery | undefined,
      recoverOverflow?: typeof compaction.compactAfterOverflow,
    ) {
      const session = yield* getSession(sessionID)
      if (session.location.directory !== location.directory || session.location.workspaceID !== location.workspaceID)
        return yield* Effect.interrupt
      const agent = yield* agents.select(session.agent)
      const initialized = yield* SessionContextEpoch.initialize(
        db,
        loadSystemContext(agent, session.id, session.scope),
        session.id,
        session.location,
        agent.id,
      ).pipe(retryAgentMismatch(promotion))
      const toolFibers = yield* FiberSet.make<void, ToolOutputStore.Error | EngagementBudget.BudgetExceededError>()
      let needsContinuation = false
      if (promotion) {
        const cutoff = yield* SessionInput.latestSeq(db, session.id)
        if (promotion === "steer") yield* SessionInput.promoteSteers(db, events, session.id, cutoff)
        if (promotion === "queue") {
          yield* SessionInput.promoteNextQueued(db, events, session.id)
          yield* SessionInput.promoteSteers(db, events, session.id, cutoff)
        }
      }
      const system =
        initialized ??
        (yield* SessionContextEpoch.prepare(
          db,
          events,
          loadSystemContext(agent, session.id, session.scope),
          session.id,
          session.location,
          agent.id,
        ).pipe(retryAgentMismatch(undefined)))
      const current = yield* getSession(sessionID)
      if ((yield* agents.select(current.agent)).id !== agent.id || !sameModel(current.model, session.model))
        return yield* Effect.die(rebuildPreparedTurn())
      const model = yield* models.resolve(session)
      const entries = yield* SessionHistory.entriesForRunner(db, session.id, system.baselineSeq)
      const context = entries.map((entry) => entry.message)
      const toolMaterialization = yield* tools.materialize(agent.info?.permissions)
      const promptCacheKey = /^ses_[0-9a-f]{64}$/.test(session.id) ? session.id.slice(4) : session.id
      const messages = toLLMMessages(context, model)
      const systemStrings = [agent.info?.system, system.baseline].filter(
        (part): part is string => part !== undefined && part.length > 0,
      )
      // Binds session.id to the async context for this turn's provider call so the
      // local pseudonymization proxy (packages/argos/.../handlers/llm-proxy.ts)
      // can key its vault deterministically off `x-engagement-id` instead of
      // guessing it from the request body. `http.headers` below is a second,
      // explicit path for transports that don't go through aisdk.ts's fetch wrapper.
      yield* Effect.sync(() => EngagementContext.enter(session.id))
      const request = LLM.request({
        model,
        providerOptions: { openai: { promptCacheKey } },
        system: systemStrings.map((s) => SystemPart.make(s)),
        messages,
        tools: toolMaterialization.definitions,
        http: { headers: { "x-engagement-id": session.id } },
      })
      if (yield* compaction.compactIfNeeded({ sessionID: session.id, entries, model, request }))
        return yield* Effect.die(rebuildPreparedTurn())
      const publisher = createLLMEventPublisher(events, {
        sessionID: session.id,
        agent: agent.id,
        model: {
          id: ModelV2.ID.make(model.id),
          providerID: ProviderV2.ID.make(model.provider),
          ...(session.model?.variant === undefined ? {} : { variant: session.model.variant }),
        },
      })
      const publication = Semaphore.makeUnsafe(1)
      const withPublication = publication.withPermit.bind(publication)
      // El consumo de tokens se descuenta del presupuesto del engagement con el
      // uso real que reporta el provider: `step-finish` es el único punto donde
      // el total de tokens de un turno ya está cerrado.
      const totalTokens = (usage: Usage | undefined) => {
        if (!usage) return 0
        const input =
          (usage.nonCachedInputTokens ?? 0) + (usage.cacheReadInputTokens ?? 0) + (usage.cacheWriteInputTokens ?? 0)
        return Math.max(0, Math.floor(input + (usage.outputTokens ?? 0)))
      }
      const publish = (event: LLMEvent, outputPaths: ReadonlyArray<string> = []) =>
        withPublication(
          Effect.gen(function* () {
            yield* publisher.publish(event, outputPaths)
            if (event.type !== "step-finish") return
            const spent = totalTokens(event.usage)
            if (spent <= 0) return
            yield* budget.consumeTokens(session.id, spent)
          }),
        )
      let overflowFailure: ProviderErrorEvent | undefined
      if (!(yield* SessionContextEpoch.current(db, session.id, agent.id, system.revision)))
        return yield* Effect.die(rebuildPreparedTurn())
      const providerStream = llm.stream(request).pipe(
        Stream.runForEach((event) =>
          Effect.gen(function* () {
            if (overflowFailure || publisher.hasProviderError()) return
            if (LLMEvent.is.providerError(event)) {
              if (isContextOverflowFailure(event) && !publisher.hasAssistantStarted()) {
                overflowFailure = event
                return
              }
            }
            yield* publish(event)
            if (event.type !== "tool-call" || event.providerExecuted) return
            needsContinuation = true
            const assistantMessageID = yield* publisher.assistantMessageID(event.id)
            yield* Effect.uninterruptibleMask((restore) =>
              restore(
                toolMaterialization.settle({
                  sessionID: session.id,
                  agent: agent.id,
                  assistantMessageID,
                  call: event,
                }),
              ).pipe(
                Effect.flatMap((settlement) =>
                  publish(
                    LLMEvent.toolResult({
                      id: event.id,
                      name: event.name,
                      result: settlement.result,
                      output: settlement.output,
                    }),
                    settlement.outputPaths ?? [],
                  ),
                ),
              ),
            ).pipe(FiberSet.run(toolFibers))
          }),
        ),
        Effect.ensuring(withPublication(publisher.flush())),
      )

      return yield* Effect.uninterruptibleMask((restore) =>
        Effect.gen(function* () {
          const stream = yield* restore(providerStream).pipe(Effect.exit)
          const failure =
            stream._tag === "Failure" ? Option.getOrUndefined(Cause.findErrorOption(stream.cause)) : undefined
          if (
            recoverOverflow &&
            !publisher.hasAssistantStarted() &&
            isContextOverflowFailure(overflowFailure ?? failure) &&
            (yield* restore(recoverOverflow({ sessionID: session.id, entries, model, request })))
          )
            return yield* Effect.die(continueAfterOverflowCompaction)
          if (overflowFailure) yield* publish(overflowFailure)
          const llmFailure = failure instanceof LLMError ? failure : undefined
          if (llmFailure && !publisher.hasProviderError()) {
            yield* withPublication(publisher.failUnsettledTools("Provider did not return a tool result", true))
            yield* withPublication(
              events.publish(SessionEvent.Step.Failed, {
                sessionID: session.id,
                timestamp: yield* DateTime.now,
                assistantMessageID: yield* publisher.startAssistant(),
                error: { type: "unknown", message: llmFailure.reason.message },
              }),
            )
          }
          if (stream._tag === "Failure" && Cause.hasInterrupts(stream.cause)) yield* FiberSet.clear(toolFibers)
          const settled = yield* restore(awaitToolFibers(toolFibers)).pipe(Effect.exit)
          if (settled._tag === "Failure" && isQuestionRejected(settled.cause)) {
            yield* FiberSet.clear(toolFibers)
            yield* withPublication(publisher.failUnsettledTools("Tool execution interrupted"))
            return yield* Effect.interrupt
          }
          if (
            (stream._tag === "Failure" && Cause.hasInterrupts(stream.cause)) ||
            (settled._tag === "Failure" && Cause.hasInterrupts(settled.cause))
          ) {
            yield* FiberSet.clear(toolFibers)
            yield* withPublication(publisher.failUnsettledTools("Tool execution interrupted"))
          }
          if (settled._tag === "Failure" && !Cause.hasInterrupts(settled.cause)) {
            const failure = Cause.squash(settled.cause)
            const message = failure instanceof Error ? failure.message : String(failure)
            yield* withPublication(publisher.failUnsettledTools(`Tool execution failed: ${message}`))
          }
          if (publisher.hasProviderError())
            yield* withPublication(publisher.failUnsettledTools("Tool execution interrupted"))
          if (stream._tag === "Success" && !publisher.hasProviderError())
            yield* withPublication(publisher.failUnsettledTools("Provider did not return a tool result", true))
          if (stream._tag === "Failure") return yield* Effect.failCause(stream.cause)
          if (settled._tag === "Failure") return yield* Effect.failCause(settled.cause)
          return !publisher.hasProviderError() && needsContinuation
        }),
      )
    }, Effect.scoped)
    type RunTurn = (
      sessionID: SessionSchema.ID,
      promotion: SessionInput.Delivery | undefined,
    ) => Effect.Effect<boolean, RunError>

    const runAfterOverflowCompaction: RunTurn = Effect.fnUntraced(function* (sessionID, promotion) {
      return yield* runTurnAttempt(sessionID, promotion).pipe(
        Effect.catchDefect(
          Effect.fnUntraced(function* (defect) {
            if (!(defect instanceof TurnTransitionError)) return yield* Effect.die(defect)
            if (defect.transition._tag === "ContinueAfterOverflowCompaction")
              return yield* Effect.die("Post-compaction provider attempt cannot recover another overflow")
            yield* Effect.yieldNow
            return yield* runAfterOverflowCompaction(sessionID, defect.transition.promotion)
          }),
        ),
      )
    })

    const runTurn: RunTurn = Effect.fnUntraced(function* (sessionID, promotion) {
      return yield* runTurnAttempt(sessionID, promotion, compaction.compactAfterOverflow).pipe(
        Effect.catchDefect(
          Effect.fnUntraced(function* (defect) {
            if (!(defect instanceof TurnTransitionError)) return yield* Effect.die(defect)
            yield* Effect.yieldNow
            if (defect.transition._tag === "ContinueAfterOverflowCompaction")
              return yield* runAfterOverflowCompaction(sessionID, undefined)
            return yield* runTurn(sessionID, defect.transition.promotion)
          }),
        ),
      )
    })

    const run = Effect.fn("SessionRunner.run")(function* (input: {
      readonly sessionID: SessionSchema.ID
      readonly force?: boolean
    }) {
      const hasSteer = yield* SessionInput.hasPending(db, input.sessionID, "steer")
      const hasQueue = hasSteer ? false : yield* SessionInput.hasPending(db, input.sessionID, "queue")
      if (input.force !== true && !hasSteer && !hasQueue) return
      const runID = yield* runJournal.start(input.sessionID)
      const execute = Effect.gen(function* () {
        yield* failInterruptedTools(input.sessionID)
        let promotion: SessionInput.Delivery | undefined = hasSteer ? "steer" : hasQueue ? "queue" : undefined
        let openActivity = input.force === true || hasSteer || hasQueue
        const session = yield* getSession(input.sessionID)
        const agent = yield* agents.select(session.agent)
        const maxSteps = agent.info?.steps ?? MAX_STEPS
        while (openActivity) {
          let needsContinuation = true
          for (let step = 0; step < maxSteps; step++) {
            needsContinuation = yield* runTurn(input.sessionID, promotion)
            promotion = "steer"
            if (!needsContinuation) needsContinuation = yield* SessionInput.hasPending(db, input.sessionID, "steer")
            if (!needsContinuation) break
          }
          if (needsContinuation)
            return yield* new StepLimitExceededError({ sessionID: input.sessionID, limit: maxSteps })
          openActivity = yield* SessionInput.hasPending(db, input.sessionID, "queue")
          promotion = openActivity ? "queue" : undefined
        }
      })
      return yield* execute.pipe(
        Effect.onExit((exit) => {
          const status: SessionSchema.RunStatus = Exit.isSuccess(exit)
            ? "completed"
            : Cause.hasInterrupts(exit.cause)
              ? "interrupted"
              : "failed"
          const error =
            status === "interrupted"
              ? "Execution interrupted"
              : status === "failed"
                ? "Execution failed; inspect persisted session events"
                : undefined
          return runJournal.finish(runID, status, error)
        }),
      )
    })

    return Service.of({
      run,
    })
  }),
)

export const defaultLayer = layer
