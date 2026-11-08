---
description: "Auditoría web acotada a las capacidades verificadas de Argos"
agent: security-web
auditProfile: web
subtask: false
---

Objetivo solicitado: **$ARGUMENTS**

Sigue las reglas de la skill auditoria-web. Usa el alcance, argos_session_id y run_id que adjunta Argos. No generes identificadores ni permisos alternativos.

Las herramientas Linux-first verificadas son web.scan, web.waf, web.csrf, web.graphql, web.jwt, web.oauth, web.prompt_injection y web.ssti, siempre que estén disponibles en esta sesión y confirmen ejecución mediante el worker y el gateway. web.sqli, web.smuggle y web.ssrf permanecen no disponibles en este perfil. No uses solicitudes directas como fallback.

Antes de los demás probes, llama `web.waf` con el alcance de la sesión. Su detección es pasiva y de mejor esfuerzo; `waf_assessment: inconclusive` no demuestra ausencia de WAF. Un proveedor identificado tampoco confirma por sí solo reglas de bloqueo activas.

Conserva el estado real de cada prueba y no reportes cobertura limpia si hubo bloqueos, degradación, truncamiento o resultados parciales. Al final resume resultados y límites; no afirmes persistencia ni exportación no confirmadas.
