# ADR 0007 — Dialecto ledger para el panel de hallazgos

Fecha: 2026-10-08
Estado: aceptada

## Contexto

El panel de hallazgos usaba el mismo lenguaje de cards redondeadas (`rounded-lg border bg-bg-surface`, `FindingDetailedCard` en `reports.tsx:197-336`, `FindingCard` en `findings-view.tsx:458-593`) que el resto del cockpit (KPIs, resúmenes, entregables). Ese look anterior no se diferenciaba de las vistas de reporte y dificultaba el escaneo denso de listas operativas. El panel adopta filas planas para distinguir las listas densas de las vistas de reporte.

## Decisión

Adoptar el dialecto ledger táctico solo en el panel de hallazgos:

- Filas planas con riel lateral de severidad (4px, color del nivel), sin cards redondeadas; fondo bg-surface, sin sombra; hover solo cambia borde a border-default.
- Cabecera de fila: estado (botón texto) + título sans 13px semibold + meta mono 10px (CWE · agente · vector). Sin pills rounded-full.
- Evidencia colapsada por defecto (Ver más), ATT&CK/IoCs en chips planos mono (sin rounded-full), barra de acciones border-t con botones ghost (Re-verificar, Ver salida completa).
- Mono + tabular-nums solo en datos (IDs, CVSS, conteos, cURL). Títulos y narrativa en sans.
- Severidad: riel + texto de nivel + rampa --severity-* existente; prohibido inventar colores.

## Consecuencias

- El panel de hallazgos abandona las cards redondeadas y las pills `rounded-full`; cualquier variante de severidad nueva debe reutilizar la rampa `--severity-*` existente.
- Alcance limitado al panel de hallazgos; el resto de superficies (KPIs, reportes, dossier) conservan su lenguaje actual.
