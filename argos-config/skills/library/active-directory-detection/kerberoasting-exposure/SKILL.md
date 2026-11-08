---
name: "kerberoasting-exposure"
description: "Detecta exposición a Kerberoasting a partir de cuentas de servicio con SPN identificadas por lan.banner_grab/port_scan, sin ejecutar la extracción de tickets (que requiere tooling no incluido)."
domain: cybersecurity
subdomain: active-directory-detection
tags: ["active-directory", "kerberoasting", "spn", "service-account", "kerberos", "credential-access"]
mitre_attack: ["T1558.003"]
nist_csf: ["PR.AA-01"]
source_adapted_from: "detecting-kerberoasting-attacks (Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita de detección en SIEM (asumía Splunk/Zeek desplegados) a evaluación de EXPOSICIÓN externa, coherente con el alcance de una auditoría de caja negra/gris con lan.*."
---

# Skill: Exposición a Kerberoasting

La skill original detecta el *ataque en curso* vía logs de Splunk/Zeek —
infraestructura que Argos no tiene desplegada en el cliente durante una
auditoría de caja negra/gris. Esta versión evalúa la **exposición** al
ataque desde lo que sí es observable externamente: presencia de Kerberos
(puerto 88) y cuentas de servicio identificables.

## Cuándo usar esta skill

- El scope de red incluye un controlador de dominio (puerto 88/TCP+UDP
  Kerberos, 389/636 LDAP, 445 SMB abiertos en el mismo host es el patrón
  típico de un DC).
- El engagement es de red interna (no aplica a scope puramente externo salvo
  que el DC esté, incorrectamente, expuesto a internet).

## Alcance y límites

Esta skill **no** solicita tickets de servicio ni intenta extraerlos
(requeriría Impacket/Rubeus, que Argos no envuelve, y constituye una
acción activa de credential access que además de técnica excede el alcance
de detección). El objetivo es identificar la **condición de exposición** —
si existen cuentas de servicio Kerberos vulnerables al patrón, no ejecutar
el ataque.

## Procedimiento

1. **Confirmar presencia de Kerberos.** `lan.port_scan`/`lan.banner_grab`
   sobre el host candidato: puerto 88 abierto junto a 389/636 (LDAP) es
   fuerte indicio de controlador de dominio Active Directory.

2. **Buscar evidencia de cuentas de servicio con SPN en fuentes ya
   disponibles.** Si el cliente entrega un export de LDAP/AD (común en
   engagements de auditoría interna con colaboración), buscar el atributo
   `servicePrincipalName` en cuentas de usuario (no de computadora) —
   cualquier cuenta de usuario con un SPN registrado es candidata a
   Kerberoasting, porque cualquier usuario autenticado del dominio puede
   solicitar su ticket de servicio sin privilegios adicionales.

3. **Correlacionar con política de contraseñas si está disponible.** El
   riesgo real de Kerberoasting depende de si la contraseña de la cuenta de
   servicio es crackeable offline — si el cliente comparte su política de
   contraseñas (longitud mínima, complejidad) para cuentas de servicio,
   documentar si es igual o más débil que la política para usuarios
   humanos (frecuente: las cuentas de servicio suelen tener contraseñas más
   antiguas y nunca rotadas, porque romper su rotación suele causar
   incidentes de servicio).

4. **Priorizar cuentas de servicio con privilegios elevados.** Una cuenta de
   servicio con SPN que además es miembro de `Domain Admins` o tiene
   delegación no restringida es el hallazgo de mayor severidad — el
   Kerberoasting exitoso contra esa cuenta específica equivale a
   compromiso de dominio completo.

5. **Si no hay export de LDAP disponible:** documentar el hallazgo como
   "condición de riesgo no verificable sin colaboración del cliente" y
   recomendar la verificación en el reporte, en vez de omitir la línea de
   investigación — es información valiosa incluso sin confirmación directa.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access |

## Salida

Persistir con `argos_memory_save`, `status: "observed"` si es
exposición de condición (sin export de LDAP), `"suspected"` si se confirmó
la presencia de SPN sobre cuenta privilegiada. `cwe: "CWE-522"`
(Insufficiently Protected Credentials). `needs_followup_by: ["security-ops"]`
para recomendación de gMSA (Group Managed Service Accounts, con rotación
automática) como remediación estructural.
