"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const drizzle_kit_1 = require("drizzle-kit");
exports.default = (0, drizzle_kit_1.defineConfig)({
    dialect: "sqlite",
    schema: ["./src/**/*.sql.ts", "./src/**/sql.ts"],
    out: "./migration",
    dbCredentials: {
        url: process.env.ARGOS_DB_URL ?? "./opencode.db",
    },
});
