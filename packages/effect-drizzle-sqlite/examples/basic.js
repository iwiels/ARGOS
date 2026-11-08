"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const sql_sqlite_bun_1 = require("@effect/sql-sqlite-bun");
const drizzle_orm_1 = require("drizzle-orm");
const sqlite_core_1 = require("drizzle-orm/sqlite-core");
const Context = __importStar(require("effect/Context"));
const Effect = __importStar(require("effect/Effect"));
const Layer = __importStar(require("effect/Layer"));
const Schema = __importStar(require("effect/Schema"));
const src_1 = require("../src");
const users = (0, sqlite_core_1.sqliteTable)("users", {
    id: (0, sqlite_core_1.integer)().primaryKey({ autoIncrement: true }),
    name: (0, sqlite_core_1.text)().notNull(),
});
const makeDatabase = src_1.EffectDrizzleSqlite.makeWithDefaults();
const sqliteLayer = sql_sqlite_bun_1.SqliteClient.layer({ filename: ":memory:", disableWAL: true });
class Database extends Context.Service()("@argos/example/Database") {
    static layer = Layer.effect(Database, makeDatabase).pipe(Layer.provide(sqliteLayer));
}
class UserStoreError extends Schema.TaggedErrorClass()("UserStoreError", {
    message: Schema.String,
    cause: Schema.optional(Schema.Defect),
}) {
}
const mapStoreError = (message) => (cause) => new UserStoreError({ message, cause });
class UserStore extends Context.Service()("@argos/example/UserStore") {
    static layer = Layer.effect(UserStore, Effect.gen(function* () {
        const db = yield* Database;
        return UserStore.of({
            migrate: Effect.fn("UserStore.migrate")(function* () {
                yield* src_1.EffectDrizzleSqlite.migrate(db, { migrationsFolder: `${import.meta.dirname}/migrations` }).pipe(Effect.mapError((cause) => new UserStoreError({ message: "Failed to migrate users", cause })));
            }),
            create: Effect.fn("UserStore.create")(function* (name) {
                yield* db
                    .insert(users)
                    .values({ name })
                    .pipe(Effect.asVoid, Effect.mapError(mapStoreError("Failed to create user")));
            }),
            rename: Effect.fn("UserStore.rename")(function* (from, to) {
                yield* db
                    .transaction(Effect.fnUntraced(function* (tx) {
                    yield* tx.insert(users).values({ name: from });
                    yield* tx.update(users).set({ name: to }).where((0, drizzle_orm_1.eq)(users.name, from));
                }), { behavior: "immediate" })
                    .pipe(Effect.asVoid, Effect.mapError(mapStoreError("Failed to rename user")));
            }),
            list: Effect.fn("UserStore.list")(function* () {
                return yield* db
                    .select()
                    .from(users)
                    .pipe(Effect.mapError(mapStoreError("Failed to list users")));
            }),
        });
    })).pipe(Layer.provide(Database.layer));
}
const program = Effect.gen(function* () {
    const userStore = yield* UserStore;
    yield* userStore.migrate();
    yield* userStore.create("Ada");
    yield* userStore.rename("Grace", "Grace Hopper");
    return yield* userStore.list();
});
const rows = await Effect.runPromise(program.pipe(Effect.provide(UserStore.layer)));
console.log(rows);
