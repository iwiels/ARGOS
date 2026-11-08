---
name: "auditoria-recon"
description: "Describe qué consultas de reconocimiento siguen bloqueadas cuando no pasan por el gateway de alcance."
---

# Skill: Auditoría de Reconocimiento (Superficie)

El estado depende de la capacidad concreta. Las herramientas de auditoría Web que confirman ejecución mediante el gateway pueden ejecutarse en live. El script local `recon-core.mjs` no tiene esa integración y devuelve `blocked`/`not-run`; tampoco se deben sustituir sus consultas al objetivo o a fuentes de terceros por solicitudes desde el host.

## Procedimiento

1. Comprueba la autorización y registra el alcance solicitado.
2. Comprueba el estado del runtime y del gateway para esta capacidad. Si la operación solicitada depende de `recon-core.mjs` o no dispone de una ruta aprobada por el gateway, informa `blocked` con cobertura `not-run`; no registres hallazgos ni resultados limpios. No generalices ese bloqueo a otras herramientas Web que sí acrediten su ejecución por el gateway.
3. No ejecutes `recon-core.mjs`, DNS queries, `webfetch`, shell requests ni consultas de terceros con el dominio objetivo como sustituto del gateway.
4. Cuando Argos habilite el gateway para esta ruta de reconocimiento, limita las fuentes externas a las capacidades aprobadas para el engagement y conserva la procedencia de cada observación.

## Salida

Estado explícito `blocked`/`not-run`; no se atribuye cobertura a una fase que no se ejecutó.
