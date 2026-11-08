# ADR 0008 — Dos capas de sesión: runtime del agente y engagement de seguridad

Fecha: 2026-10-22
Estado: aceptada
Reemplaza: ninguna
Relacionada: ARG-065

## Contexto

El repositorio tiene dos árboles llamados `session` y varias piezas con el mismo
nombre de archivo. La ambigüedad no es teórica: quien toca `session/prompt.ts`
puede estar editando la construcción del prompt del modelo o el esquema de una
entrada de prompt persistida, y son cosas distintas.

- `packages/argos/src/session/` (22 archivos): el **runtime del agente**. El
  servicio `Session`, el bucle `processor` + `llm`, el modelo V1 de mensajes y
  partes, la construcción de prompt del sistema, compactación del turno actual,
  `revert`, `status` y `run-state`.
- `packages/core/src/session/` (20 archivos más `execution/` y `runner/`): el
  **registro del engagement**. Persistencia (`store`, `sql`, `projector`),
  esquema y eventos, historial, presupuesto, kill-switch, `run-coordinator`,
  época de contexto y la proyección persistida de todos.

La frontera ya existe en el código y es de una sola dirección:

- `packages/argos/src/session/*` importa `@argos/core/*` (por ejemplo
  `compaction.ts` usa `SessionV1`, `Message`, `Token`).
- `packages/core/src/session/*` no importa `@argos/argos`, `@argos/server` ni
  `@argos/app`. Verificado por búsqueda de imports en todo el árbol.

Lo que faltaba era la regla explícita: el chequeo `.arch-rules.json` prohibía a
core importar `server`, `app` y `desktop`, pero **no** `packages/argos`, que es
justamente el paquete que sí depende de core. La regla se agrega en este cambio.

## Decisión

1. **`@argos/core/session` es la única fuente de verdad del engagement.** Todo
   lo que el informe, el panel, el log encadenado y el compliance necesitan leer
   vive ahí y se escribe por el store de core.
2. **`packages/argos/src/session` es el bucle del modelo.** Construye prompts,
   llama al LLM, compacta el contexto, reintenta, revierte y expone estado del
   turno. No es dueño de hallazgos, evidencia, presupuesto ni auditoría.
3. **Dirección de dependencia obligatoria:** `argos → core`. Nunca al revés.
   Se hace cumplir en `.arch-rules.json` (`core-no-application-dependency`
   incluye `packages/argos`) y corre como gate bloqueante.
4. **Un solo `sessionID`.** Los dos árboles operan sobre el mismo identificador
   `ses_...`. No se crea un id paralelo para el engagement: rompería la
   reconciliación de hallazgos con la sesión abierta.
5. **Toda escritura de hallazgo pasa por el bridge del servidor** (ingest o
   `argos_memory_save` con `argos_session_id`), nunca por un import directo del
   agente al store. Es la condición para que el hallazgo entre en el log
   encadenado y sea retesteable.

### Nombres homónimos: qué es cada uno

| Archivo | `packages/argos/src/session` | `packages/core/src/session` |
|---|---|---|
| `prompt.ts` | Prompt del sistema e instrucciones del turno | Esquema de una entrada de prompt (fuentes, adjuntos) |
| `message.ts` | Modelo V1 de mensajes/partes para el proveedor | Mensaje persistido V2 y eventos |
| `compaction.ts` | Decide y ejecuta la compactación del turno | Compactación persistida sobre el historial |
| `todo.ts` | Estado del tool de todos para el agente | **Duplicado real:** ambos escriben `TodoTable` |
| `schema.ts` | Identificadores del runtime | Esquema de la base |

`todo.ts` es el único caso de lógica duplicada. El resto comparte nombre por
herencia, no por responsabilidad.

## Consecuencias

- Un cambio en core/session puede romper el runtime de argos; el gate de
  arquitectura no lo impide, pero el typecheck sí. Es el costo aceptado de
  tener el registro auditable en el paquete puro.
- La UI no puede leer core directamente: sigue hablando con el servidor. La
  regla `app-no-direct-server-dependency` ya lo prohíbe.
- Los tests de core no necesitan levantar el runtime del agente: es una ventaja
  de la separación y hay que preservarla (nada de imports de `argos` en tests
  de core).

## Plan de convergencia

| Fase | Trabajo | Estado |
|---|---|---|
| A | Congelar la frontera y hacerla gate (esta ADR + `.arch-rules.json`) | Hecho |
| B | Colapsar `argos/src/session/todo.ts` en el servicio `SessionTodo` de core: un solo escritor de `TodoTable` | Pendiente |
| C | Retirar el modelo V1 de `argos/src/session/message.ts` cuando el compat layer V1 deje de usarse; entonces argos/session queda sólo como bucle del modelo | Pendiente, depende del retiro de V1 |
| D | Partir `packages/app/src/pages/session.tsx` (1.436 líneas, complejidad 1.384): cola de follow-ups, panel de review, historial/scroll | Parcial; el archivo ya delega en `pages/session/*` y este ADR fija el orden |

La fase D no es parte de esta frontera: es deuda de UI. Se documenta acá porque
el plan ARG-065 la agrupa con la sesión y conviene no confundir las dos.

## Alternativas descartadas

- **Unificar los dos paquetes en `core`.** Metería el bucle del modelo y sus
  dependencias de proveedor en el paquete que hoy es puro y testeable sin red.
- **Renombrar `argos/src/session` a `runtime/`.** Cosmético, rompe imports
  masivos y no cambia la regla; el valor está en la dirección de dependencia,
  no en el nombre de la carpeta.
- **Permitir que el agente escriba hallazgos directo en el store.** Elimina la
  reconciliación por `sessionID` y el log encadenado: es exactamente el
  problema que ARG-001/ARG-053 vinieron a cerrar.
