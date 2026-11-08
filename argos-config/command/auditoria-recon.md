---
description: "Preset · Reconocimiento pasivo con procedencia y límites explícitos"
agent: security-scout
---

# Reconocimiento pasivo

Objetivo solicitado: **$ARGUMENTS**

Usa únicamente fuentes públicas pasivas que estén disponibles y autorizadas para esta sesión. El alcance de Argos y los identificadores de sesión los proporciona el controlador; no inventes SESSION_ID, campaign label ni run_id.

No ejecutes recon-core, DNS queries, solicitudes HTTP ni consultas externas con el target mientras el runtime no confirme que ese tipo de tráfico está permitido y controlado. No sustituyas el gateway con shell, webfetch ni scripts locales.

Entrega observaciones con fuente, fecha y confianza. Si una fuente no está disponible, informa ese límite. No inventes activos, persistencia en el expediente ni cobertura de pruebas activas.
