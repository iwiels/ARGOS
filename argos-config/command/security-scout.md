---
description: "Reconocimiento pasivo limitado a fuentes disponibles y autorizadas"
agent: security-scout
---

Objetivo solicitado: **$ARGUMENTS**

Realiza reconocimiento pasivo solo mediante fuentes y herramientas disponibles en esta sesión. Usa el objetivo y los identificadores entregados por Argos; no generes SESSION_ID ni etiquetas de campaña.

No hagas DNS queries, solicitudes HTTP, enumeración de hosts ni consultas a terceros con el objetivo como dato hasta que el runtime confirme que esa actividad está aprobada y enruta su tráfico según el alcance. No uses scripts locales como fallback.

Distingue observaciones de inferencias y conserva la fuente. Informa lo que no se pudo consultar. La falta de resultados no demuestra que el objetivo esté libre de riesgos. No afirmes que guardaste hallazgos en el expediente sin confirmación de Argos.
