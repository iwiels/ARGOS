---
description: "Coordina análisis acotados con los agentes y herramientas disponibles en Argos"
agent: security-orchestrator
---

Objetivo solicitado: **$ARGUMENTS**

Coordina el análisis dentro del alcance y las capacidades que Argos confirme en la sesión actual. El controlador proporciona los identificadores de sesión y ejecución. No crees SESSION_ID, campaign labels, autorizaciones ni run_id.

Delega solo subtareas concretas y espera sus respuestas antes de presentar conclusiones. Cada hijo puede tener una sesión y ejecución propias; no presupongas que comparte persistencia o cobertura con el padre.

No consultes una memoria o fuente de autorización como sustituto del alcance configurado. No uses scanners, llamadas a red ni comandos locales fuera del runtime aprobado. Marca como incompletas las tareas que no devolvieron resultados verificables.

Entrega una síntesis de lo que realmente se ejecutó, evidencia disponible, cobertura faltante y motivos. No prometas un informe exportado ni una deduplicación persistida salvo confirmación de Argos.
