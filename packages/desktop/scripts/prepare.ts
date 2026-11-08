#!/usr/bin/env bun
await import("./prebuild")

const pkg = await Bun.file("./package.json").json()
await Bun.write("./package.json", JSON.stringify(pkg, null, 2) + "\n")
console.log(`Package version: ${pkg.version}`)




