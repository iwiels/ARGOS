---
name: "ntlm-relay-exposure"
description: "Detecta condiciones que habilitan NTLM relay (SMB signing no requerido, LDAP sin firmado/channel binding) a partir de evidencia de banner/negociación de lan.banner_grab, sin ejecutar el relay activo."
domain: cybersecurity
subdomain: active-directory-detection
tags: ["active-directory", "ntlm-relay", "smb-signing", "ldap-signing", "coercion", "credential-access"]
mitre_attack: ["T1557.001"]
nist_csf: ["PR.IR-01"]
source_adapted_from: "detecting-ntlm-relay-with-event-correlation / configuring-ldap-security-hardening (Anthropic-Cybersecurity-Skills, Apache-2.0) — consolidadas en detección de EXPOSICIÓN (configuración), no ejecución del relay (que requiere Responder/ntlmrelayx, no incluidos)."
---

# Skill: Exposición a NTLM relay

NTLM relay sigue siendo una de las rutas más confiables de escalación en
redes Windows internas, y depende casi por completo de una condición de
configuración verificable sin herramientas de explotación: si SMB/LDAP
firman sus sesiones o no.

## Cuándo usar esta skill

- El scope de red interna incluye múltiples hosts Windows, especialmente si
  hay un controlador de dominio (LDAP en 389/636) además de hosts con SMB
  (445).

## Alcance y límites

Esta skill **no** ejecuta Responder ni ntlmrelayx — ninguno está en el
motor MCP de Argos, y su ejecución (envenenamiento activo de
LLMNR/NBT-NS, relay de autenticación capturada) es una acción de
explotación activa que requiere aprobación de fase OLA2 explícita, no una
detección pasiva. El objetivo aquí es identificar la **condición
habilitante** — firma no requerida — que es lo auditable sin ejecutar el
ataque.

## Procedimiento

1. **Verificar el requisito de firma SMB del lado servidor**, si es
   detectable en la negociación capturada por `lan.banner_grab`. La
   condición vulnerable es "SMB signing: enabled but not required" — el
   valor peligroso no es la ausencia total de firma (poco común hoy) sino
   que sea *opcional*, lo que permite a un cliente atacante negociar sin
   firma y relayear la autenticación capturada.

2. **Verificar LDAP signing y LDAP channel binding en el controlador de
   dominio**, si el cliente entrega configuración o si es inferible de la
   negociación LDAP. Desde 2020, Microsoft recomienda ambos como
   requeridos; su ausencia es la condición que habilita relay de NTLM hacia
   LDAP con capacidad de escritura sobre el directorio (el vector más
   grave de esta clase, porque puede derivar en creación de objetos con
   delegación o modificación de ACLs).

3. **Identificar mecanismos de coerción de autenticación en la red.**
   Servicios que un atacante en la misma red podría usar para forzar a un
   host (incluyendo cuentas de máquina con privilegios, como el propio DC)
   a autenticarse hacia un endpoint controlado — spooler de impresión
   expuesto, WebDAV, o servicios de notificación de cambios. Esta skill no
   ejecuta la coerción; documenta si el servicio está presente en la
   superficie observada.

4. **Priorizar por lo que la firma faltante protege.** LDAP sin firmar en
   el DC es crítico (relay con escritura al directorio). SMB sin firmar
   entre workstations es menor (relay limitado al alcance de esa máquina
   específica) salvo que apunte a un host con privilegios.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | Credential Access, Collection |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-300"` (Channel
Accessible by Non-Endpoint) para firma opcional/ausente. `severity:
"critical"` si es LDAP sin channel binding en un DC, `"high"` para SMB
signing opcional en hosts con privilegios. `status: "observed"` — esta
skill documenta condición, no explotación confirmada.
