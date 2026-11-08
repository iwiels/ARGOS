# ADR 0009 — Effect 4 beta: riesgo aceptado y criterio de salida

Fecha: 2026-10-22
Estado: aceptada
Relacionada: ARG-065

## Contexto

Todo el backend de `packages/core` corre sobre `effect@4.0.0-beta.74` y sus
paquetes acompañantes, fijados exactamente en el catálogo de
`pnpm-workspace.yaml`:

```
effect, @effect/platform, @effect/platform-node, @effect/sql,
@effect/sql-sqlite-bun, @effect/cluster, @effect/rpc,
@effect/experimental, @effect/workflow  →  4.0.0-beta.74
```

No existe hoy una combinación estable de Effect 4 que ofrezca las APIs que el
código usa (streams, `Layer`, `Schema`, SQL, RPC). Migrar a Effect 3 implicaría
reescribir el backend. Por eso el beta es una decisión, no un descuido.

El costo ya se materializó una vez: la interfaz `FileSystem` de
`effect@4.0.0-beta.74` declara `realPath`, pero la implementación concreta de
`@effect/platform-node@4.0.0-beta.74` no lo implementa. Llamarlo resuelve a un
no-op silencioso. El workaround vive en `packages/core/src/fs-util.ts`, que
resuelve `realPath` contra `node:fs/promises` en lugar de la capa de plataforma.

## Decisión

1. **Se acepta el riesgo del beta** mientras no exista un 4.x estable con paridad
   de APIs. La versión se fija exacta, nunca con rango flotante, y se actualiza
   en un solo lugar (`pnpm-workspace.yaml`).
2. **El parche de `realPath` queda aislado y documentado** en `fs-util.ts`, con
   un comentario que explica por qué existe y cuándo se retira. Ningún otro
   módulo parchea la plataforma.
3. **Los tests no dependen del comportamiento del parche más allá del wrapper:**
   si `@effect/platform-node` lo implementa, el wrapper debe seguir pasando sin
   cambios.
4. **Criterio de salida** (los tres a la vez):
   - Effect publica un 4.x estable.
   - `@effect/platform-node` implementa `FileSystem.realPath`.
   - La suite de `packages/core` pasa sin el parche.
   Al cumplirse: se elimina el workaround, se sube el catálogo, se borra la
   excepción de este ADR y se anota el cambio en `AGENTS.md`.

## Consecuencias

- Un bug del beta se reproduce contra una versión exacta y se documenta; no se
  "prueba suerte" subiendo de beta.
- Actualizar Effect es un cambio deliberado con revisión de changelog, no una
  actualización automática de dependencias.
- El parche es deuda visible: cualquier `realPath` que se agregue en el futuro
  debe pasar por `fs-util.ts`, no por la capa de plataforma directa.

## Alternativas descartadas

- **Quedarse en Effect 3.** Reescritura del backend y de los adaptadores SQL;
  el código ya está escrito contra la API 4.
- **Vendorizar el paquete y parchear `@effect/platform-node`.** Duplica un
  paquete grande, complica el lockfile y traslada el problema al supply chain.
- **Evitar `realPath` en todo el código.** No es viable: la resolución de rutas
  reales es necesaria para el scope y para el aislamiento de archivos.
