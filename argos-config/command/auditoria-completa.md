---
description: "Preset · Auditoría Web/API y repositorio según las capacidades disponibles"
agent: security-orchestrator
---

# Auditoría Web/API y repositorio

Objetivo solicitado: **$ARGUMENTS**

Ejecuta solo las pruebas que el controlador, el alcance configurado y las herramientas disponibles permitan. Usa los identificadores de sesión y ejecución suministrados por Argos; no inventes SESSION_ID ni campaign label.

En el primer hito Linux-first, las pruebas activas Web/API deben usar el worker aislado y el gateway de alcance. El análisis de repositorio se limita al código que el operador haya abierto o proporcionado y a las herramientas que confirmen una ejecución completa.

LAN, navegador, autenticación automatizada y otras capacidades no confirmadas no forman parte de una auditoría completa en este perfil. Identifícalas como no ejecutadas o bloqueadas, con el motivo real. No uses comandos locales como alternativa a un scanner deshabilitado.

Entrega en la sesión un resumen de alcance, pruebas ejecutadas, hallazgos basados en evidencia y limitaciones. No afirmes que un archivo fue exportado ni que un hallazgo se persistió hasta que Argos confirme esa operación.
