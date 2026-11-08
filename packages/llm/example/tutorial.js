"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const effect_1 = require("effect");
const llm_1 = require("@argos/llm");
const route_1 = require("@argos/llm/route");
const providers_1 = require("@argos/llm/providers");
/**
 * A runnable walkthrough of the LLM package use-site API.
 *
 * Run from `packages/llm` with an OpenAI key in the environment:
 *
 *   OPENAI_API_KEY=... bun example/tutorial.ts
 *
 * The file is intentionally written as a normal TypeScript program. You can
 * hover imports and local values to see how the public API is typed.
 */
const apiKey = effect_1.Config.redacted("OPENAI_API_KEY");
// 1. Pick a model. The provider helper records provider identity, protocol
// choice, capabilities, deployment options, authentication, and defaults.
const model = providers_1.OpenAI.configure({
    apiKey,
    generation: { maxTokens: 160 },
    providerOptions: {
        openai: { store: false },
    },
}).model("gpt-4o-mini");
// 2. Build a provider-neutral request. This is useful when reusing one request
// across generate and stream examples.
//
// Options can live on both the configured route/provider facade and the request:
//
//   - `generation`: common controls such as max tokens, temperature, topP/topK,
//     penalties, seed, and stop sequences.
//   - `providerOptions`: namespaced provider-native behavior. For example,
//     OpenAI cache keys and store behavior, Anthropic thinking, Gemini thinking
//     config, or OpenRouter routing/reasoning.
//   - `http`: last-resort serializable overlays for final request body, headers,
//     and query params. Prefer typed `providerOptions` when a field is stable.
//
// Route/provider options are defaults. Request options override them for this call.
const request = llm_1.LLM.request({
    model,
    system: "You are concise and practical.",
    prompt: "Tell me a joke",
    generation: { maxTokens: 80, temperature: 0.7 },
    providerOptions: {
        openai: { promptCacheKey: "tutorial-joke" },
    },
});
// `http` is intentionally not needed for normal calls. This shows the shape for
// newly released provider fields before they deserve a typed provider option.
const rawOverlayExample = llm_1.LLM.request({
    model,
    prompt: "Show the final HTTP overlay shape.",
    http: {
        body: { metadata: { example: "tutorial" } },
        headers: { "x-opencode-tutorial": "1" },
        query: { debug: "1" },
    },
});
// 3. `generate` sends the request and collects the event stream into one
// response object. `response.text` is the collected text output.
const generateOnce = effect_1.Effect.gen(function* () {
    const response = yield* llm_1.LLM.generate(request);
    console.log("\n== generate ==");
    console.log("generated text:", response.text);
    console.log("usage", effect_1.Formatter.formatJson(response.usage, { space: 2 }));
});
// 4. `stream` exposes provider output as common `LLMEvent`s for UIs that want
// incremental text, reasoning, tool input, usage, or finish events.
const streamText = llm_1.LLM.stream(request).pipe(effect_1.Stream.tap((event) => effect_1.Effect.sync(() => {
    if (event.type === "text-delta")
        process.stdout.write(`\ntext: ${event.text}`);
    if (event.type === "finish")
        process.stdout.write(`\nfinish: ${event.reason}\n`);
})), effect_1.Stream.runDrain);
// 5. Tools are typed with Effect Schema. Provider turns remain explicit:
// advertise definitions on the request, stream one turn, dispatch local calls,
// then persist/build follow-up history in the enclosing product flow.
const tools = {
    get_weather: llm_1.Tool.make({
        description: "Get current weather for a city.",
        parameters: effect_1.Schema.Struct({ city: effect_1.Schema.String }),
        success: effect_1.Schema.Struct({ forecast: effect_1.Schema.String }),
        execute: (input) => effect_1.Effect.succeed({ forecast: `${input.city}: sunny, 72F` }),
    }),
};
const streamWithTools = effect_1.Effect.gen(function* () {
    const request = llm_1.LLM.request({
        model,
        prompt: "Use get_weather for San Francisco, then answer in one sentence.",
        generation: { maxTokens: 80, temperature: 0 },
        tools: llm_1.Tool.toDefinitions(tools),
    });
    const events = Array.from(yield* llm_1.LLM.stream(request).pipe(effect_1.Stream.runCollect));
    for (const event of events) {
        if (event.type === "tool-call")
            console.log("tool call", event.name, event.input);
        if (event.type === "text-delta")
            process.stdout.write(event.text);
        if (event.type !== "tool-call" || event.providerExecuted)
            continue;
        const dispatched = yield* llm_1.ToolRuntime.dispatch(tools, event);
        console.log("tool result", event.name, dispatched.result);
        // A durable agent would persist these messages before starting another
        // raw model turn. This tutorial keeps the boundary visible instead.
        const followUp = llm_1.LLM.updateRequest(request, {
            messages: [
                ...request.messages,
                llm_1.Message.assistant([event]),
                llm_1.Message.tool(Object.assign(Object.assign({}, event), { result: dispatched.result })),
            ],
        });
        console.log("follow-up history messages:", followUp.messages.length);
    }
});
// 6. `generateObject` is the structured-output helper. It forces a synthetic
// tool call internally, so the same call site works across providers instead of
// depending on provider-specific JSON mode flags.
const WeatherReport = effect_1.Schema.Struct({
    city: effect_1.Schema.String,
    forecast: effect_1.Schema.String,
    highFahrenheit: effect_1.Schema.Number,
});
const generateStructuredObject = effect_1.Effect.gen(function* () {
    const response = yield* llm_1.LLM.generateObject({
        model,
        system: "Return only structured weather data.",
        prompt: "Give me today's weather for San Francisco.",
        schema: WeatherReport,
        generation: { maxTokens: 120, temperature: 0 },
    });
    console.log("\n== generateObject ==");
    console.log(effect_1.Formatter.formatJson(response.object, { space: 2 }));
});
// If the shape is only known at runtime, pass raw JSON Schema instead. The
// `.object` type is `unknown`; callers that need static types should validate it.
const generateDynamicObject = llm_1.LLM.generateObject({
    model,
    prompt: "Extract the city and forecast from: San Francisco is sunny.",
    jsonSchema: {
        type: "object",
        properties: {
            city: { type: "string" },
            forecast: { type: "string" },
        },
        required: ["city", "forecast"],
    },
});
// -----------------------------------------------------------------------------
// Part 2: provider composition with a fake provider
// -----------------------------------------------------------------------------
// A protocol is the provider-native API shape: common request -> body, response
// frames -> common events. This fake one turns text prompts into a JSON body
// and treats every SSE frame as output text.
const FakeBody = effect_1.Schema.Struct({
    model: effect_1.Schema.String,
    input: effect_1.Schema.String,
});
const FakeProtocol = route_1.Protocol.make({
    // Protocol ids are open strings, so external packages can define their own
    // protocols without changing this package.
    id: "fake-echo",
    body: {
        schema: FakeBody,
        from: (request) => effect_1.Effect.succeed({
            model: request.model.id,
            input: request.messages
                .flatMap((message) => message.content)
                .filter((part) => part.type === "text")
                .map((part) => part.text)
                .join("\n"),
        }),
    },
    stream: {
        event: effect_1.Schema.String,
        initial: () => undefined,
        step: (_, frame) => effect_1.Effect.succeed([undefined, [{ type: "text-delta", id: "text-0", text: frame }]]),
        onHalt: () => [{ type: "finish", reason: "stop" }],
    },
});
// An route is the runnable binding for that protocol. It adds the deployment
// axes that the protocol deliberately does not know: URL, auth, and framing.
const FakeAdapter = route_1.Route.make({
    id: "fake-echo",
    provider: "fake-echo",
    protocol: FakeProtocol,
    endpoint: route_1.Endpoint.path("/v1/echo", { baseURL: "https://fake.local" }),
    auth: route_1.Auth.passthrough,
    framing: route_1.Framing.sse,
});
// A provider module exports a configured facade. Configuration happens before
// model selection; model selectors accept ids only.
const FakeEcho = {
    id: llm_1.ProviderID.make("fake-echo"),
    configure: () => ({
        id: llm_1.ProviderID.make("fake-echo"),
        model: (id) => FakeAdapter.model({ id }),
    }),
};
// `LLMClient.prepare` is the lower-level inspection hook: it compiles through
// body conversion, validation, endpoint, auth, and HTTP construction without
// sending anything over the network.
const inspectFakeProvider = effect_1.Effect.gen(function* () {
    const prepared = yield* llm_1.LLMClient.prepare(llm_1.LLM.request({
        model: FakeEcho.configure().model("tiny-echo"),
        prompt: "Show me the provider pipeline.",
    }));
    console.log("\n== fake provider prepare ==");
    console.log("route:", prepared.route);
    console.log("body:", effect_1.Formatter.formatJson(prepared.body, { space: 2 }));
});
// Provide the LLM runtime and the HTTP request executor once. Keep one path
// enabled at a time so the tutorial can demonstrate generate, prepare, stream,
// or tool-loop behavior without spending tokens on every example.
const requestExecutorLayer = route_1.RequestExecutor.defaultLayer;
const llmDeps = effect_1.Layer.mergeAll(requestExecutorLayer, route_1.WebSocketExecutor.layer);
const llmClientLayer = llm_1.LLMClient.layer.pipe(effect_1.Layer.provide(llmDeps));
const program = effect_1.Effect.gen(function* () {
    // yield* generateOnce
    // yield* inspectFakeProvider
    // yield* LLMClient.prepare(rawOverlayExample).pipe(Effect.andThen((prepared) => Effect.sync(() => console.log(prepared.body))))
    // yield* streamText
    // yield* generateStructuredObject
    // yield* generateDynamicObject.pipe(Effect.andThen((response) => Effect.sync(() => console.log(response.object))))
    yield* streamWithTools;
}).pipe(effect_1.Effect.provide(effect_1.Layer.mergeAll(llmDeps, llmClientLayer)));
void effect_1.Effect.runPromise(program);
