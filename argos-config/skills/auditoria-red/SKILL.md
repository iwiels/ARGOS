---
name: "auditoria-red"
description: "Informa el estado del escáner LAN sin ejecutar sondeos locales."
---

# Auditoría LAN

La auditoría LAN no forma parte del perfil de escritorio habilitado en este hito.

1. Comprueba si la tool MCP argos-lan está disponible en la sesión actual y si el controlador confirma un alcance CIDR autorizado.
2. Si falta la tool, el preflight o el alcance, detén la actividad y reporta la prueba como bloqueada o no ejecutada. No llames a Nmap, Naabu, lan-core, shell ni otro scanner local como alternativa.
3. No inventes hosts, puertos, topología, severidad ni hallazgos. No afirmes que los datos se guardaron en Argos si la aplicación no confirma el registro.
4. Si el runtime cambia y habilita LAN, usa solamente las tools que exponga y conserva su salida verificable. Indica los límites y fallos de cada fase.

El cierre debe distinguir entre una auditoría LAN no ejecutada y una auditoría completada. La ausencia de resultados no demuestra que la red esté libre de riesgos.
