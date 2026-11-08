---
name: "smb-null-session-exposure"
description: "Detecta enumeración anónima SMB (null session) y shares accesibles sin autenticación, a partir de lan.banner_grab/port_scan sobre el puerto 445."
domain: cybersecurity
subdomain: active-directory-detection
tags: ["active-directory", "smb", "null-session", "anonymous-enumeration", "network-share"]
mitre_attack: ["T1135", "T1046"]
nist_csf: ["PR.AA-05"]
source_adapted_from: "Consolidada de varias skills de detección de red del repo original (Anthropic-Cybersecurity-Skills, Apache-2.0), acotada al patrón SMB null session con lan.banner_grab en vez de herramientas SMB dedicadas (smbclient/enum4linux)."
---

# Skill: Exposición de sesión nula SMB

SMB null session — autenticación anónima habilitada sobre el protocolo SMB
— es un remanente frecuente en redes con Windows Server más antiguo o
configuración heredada, y sigue siendo la forma más simple de enumerar
usuarios, grupos y shares sin ninguna credencial.

## Cuándo usar esta skill

- El scope de red incluye hosts Windows con el puerto 445/TCP (SMB) abierto.

## Alcance y límites

`lan.banner_grab` puede confirmar el puerto abierto y, según lo que exponga
el banner/negociación inicial, indicios de la versión de protocolo SMB. La
enumeración completa de shares/usuarios vía sesión nula normalmente requiere
`smbclient`/`enum4linux`, que Argos no envuelve — esta skill se limita
a **confirmar la condición de exposición** (puerto abierto + versión
vulnerable si es detectable) y documentarla como línea de investigación,
sin ejecutar la enumeración completa.

## Procedimiento

1. **Confirmar el puerto y, si es posible, la versión SMB.**
   `lan.port_scan`/`lan.banner_grab` sobre 445/TCP. SMBv1 habilitado (aunque
   sea junto a versiones más nuevas) es en sí un hallazgo — es el protocolo
   vulnerable a EternalBlue y a la mayoría de las técnicas de relay más
   antiguas, y Microsoft lo deprecó por razones de seguridad, no solo de
   rendimiento.

2. **Si el engagement tiene colaboración del cliente o herramientas
   adicionales aprobadas explícitamente en el alcance:** documentar el
   protocolo exacto de verificación de sesión nula usado (fuera del alcance
   por defecto de esta skill, requiere aprobación explícita del engagement
   para el tooling adicional).

3. **Correlacionar con la topología de red.** Si `lan.build_topology`
   identificó el host como controlador de dominio o servidor de archivos,
   la exposición de SMB null session en ese host específico tiene mayor
   impacto (puede enumerar la estructura completa del dominio) que en un
   host de workstation aislado.

4. **Revisar si el firmado SMB (SMB signing) está habilitado**, si el
   banner/negociación lo revela — SMB signing deshabilitado o solo
   "preferido" (no "requerido") es la condición que habilita ataques de
   NTLM relay contra ese mismo host (ver skill
   `ntlm-relay-exposure`), y suele coexistir con null session en
   configuraciones heredadas.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1135 | Network Share Discovery | Discovery |
| T1046 | Network Service Discovery | Discovery |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-287"` (Improper
Authentication) para null session confirmada, o documentar como
`status: "observed"` la condición de puerto SMB expuesto con SMBv1 activo
si la enumeración completa está fuera del alcance de las tools disponibles.
`severity: "high"` si el host es un DC o file server identificado por la
topología.
