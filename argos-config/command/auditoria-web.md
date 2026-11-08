---
description: "Preset · Auditoría Web — pruebas disponibles en el runtime aislado de Argos"
agent: security-orchestrator
auditProfile: web
---

# Auditoría Web

Objetivo solicitado: **$ARGUMENTS**

Realiza una auditoría Web/API dentro del alcance configurado en Argos. El controlador entrega el argos_session_id, el run_id y la instantánea de alcance; nunca los inventes ni uses una etiqueta de campaña para reemplazarlos.

Antes de generar tráfico, confirma que el alcance esté disponible y usa únicamente herramientas argos-web que estén conectadas al worker aislado y al gateway. No hagas solicitudes directas desde shell, navegador, webfetch, curl, fetch o scripts locales.

Ejecuta `web.waf` antes del primer scan o probe Web/API. Es una huella pasiva de proveedor basada en una petición normal: si devuelve `waf_assessment: inconclusive`, informa que no se observó una huella conocida; no concluyas que no existe WAF.

El runtime Linux-first verificado permite web.scan, web.waf y los probes web.csrf, web.graphql, web.jwt, web.oauth, web.prompt_injection y web.ssti. web.sqli, web.smuggle y web.ssrf informan que no están disponibles en este perfil. Para cualquier otra herramienta, conserva el resultado real y no des por hecha su cobertura.

Clasifica cada prueba como ejecutada, sin hallazgo, bloqueada, omitida o inconclusa. Un resultado abortado, degradado, truncado o con dependencia ausente no equivale a un resultado limpio. No inventes hallazgos ni datos de severidad; conserva la salida verificable de las tools.

Entrega en la sesión un resumen de alcance, pruebas realizadas, resultados y limitaciones. No afirmes que exportaste un archivo ni que se validó un hallazgo de forma independiente a menos que la aplicación confirme esa operación.
