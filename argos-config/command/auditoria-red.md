---
description: "Preset · LAN — informar disponibilidad del escáner de red sin usar fallback local"
agent: security-orchestrator
---

# Auditoría LAN

Objetivo solicitado: **$ARGUMENTS**

En el perfil actual, la auditoría LAN no está habilitada en el escritorio. No ejecutes comandos locales, Nmap, Naabu u otros scanners como alternativa.

Comprueba si el runtime Argos informa una tool LAN disponible y si su preflight y alcance están configurados. Si no están disponibles, informa que la prueba quedó bloqueada y no ejecutes tráfico de red. La autorización debe formar parte del alcance configurado por el operador; una etiqueta o registro de memoria no la sustituye.

No inventes hosts, puertos, topología, hallazgos ni reportes. Si el runtime está disponible, usa solo las tools que expone y conserva sus resultados verificables.
