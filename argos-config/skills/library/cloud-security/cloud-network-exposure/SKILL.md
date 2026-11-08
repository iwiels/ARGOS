---
name: "cloud-network-exposure"
description: "Detecta puertos y servicios de gestión (SSH, RDP, bases de datos, paneles de administración) expuestos a internet en infraestructura cloud, mediante lan.port_scan y correlación con exports de security groups del cliente."
domain: cybersecurity
subdomain: cloud-security
tags: ["cloud", "network-exposure", "security-group", "nsg", "exposed-management-port", "0.0.0.0/0"]
mitre_attack: ["T1133", "T1046"]
nist_csf: ["PR.IR-01", "PR.AA-05"]
source_adapted_from: "auditing-terraform-infrastructure-for-security (Anthropic-Cybersecurity-Skills, Apache-2.0) — acotada a la parte de exposición de red, que sí es verificable con las tools de Argos sin necesidad de parsear Terraform."
---

# Skill: Exposición de red en infraestructura cloud

Correlaciona lo que `lan.port_scan`/`lan.host_discovery` observan
externamente con la configuración de red que el cliente entrega (security
groups de AWS, NSGs de Azure, firewall rules de GCP) para distinguir "está
abierto porque debe estarlo" de "está abierto por error de configuración".

## Cuándo usar esta skill

- El scope incluye rangos de IP o hosts que resultan ser instancias cloud
  (identificable por rDNS, banners, o rangos ASN conocidos de AWS/Azure/GCP).
- El cliente entrega un export de reglas de firewall/security group.

## Alcance y límites

El escaneo de puertos ya lo hace `lan.port_scan` — esta skill no reemplaza
esa tool, la interpreta con criterio de "qué no debería estar expuesto a
internet" en un contexto cloud, que es distinto al de una LAN corporativa
tradicional (donde cierta exposición interna es esperable).

## Procedimiento

1. **Ejecutar o reutilizar resultados de `lan.port_scan`** sobre los hosts en
   scope. Priorizar la lectura sobre los puertos de gestión y datos:
   `22` (SSH), `3389` (RDP), `3306`/`5432` (MySQL/Postgres), `6379` (Redis),
   `9200` (Elasticsearch), `27017` (MongoDB), `2379` (etcd) — bases de datos
   sin autenticación por defecto son el patrón más costoso.

2. **Clasificar cada puerto abierto contra su expectativa razonable:**
   - Un puerto de base de datos accesible desde `0.0.0.0/0` es casi siempre
     un hallazgo — las bases de datos deberían estar en subred privada,
     accesibles solo desde la capa de aplicación.
   - SSH/RDP expuestos son aceptables si están detrás de MFA/bastion y el
     cliente lo confirma como diseño intencional; si no, es hallazgo.
   - Servicios de gestión de Kubernetes (`kubelet` 10250, API server 6443)
     expuestos sin autenticación son crítico automático.

3. **Si hay export de security groups/NSGs:** buscar reglas con
   `0.0.0.0/0` o `::/0` como source, especialmente combinadas con puertos de
   la lista anterior. Citar la regla exacta (ID del security group, puerto,
   CIDR) junto al puerto confirmado abierto por el escaneo — la combinación
   de ambas evidencias es más fuerte que cualquiera por separado.

4. **Distinguir "expuesto" de "vulnerable".** Un servicio expuesto pero
   parchado y con autenticación fuerte es un hallazgo de menor severidad
   (reduce superficie de ataque) que uno expuesto y sin autenticación
   (acceso directo). No escalar automáticamente todo puerto abierto a
   severidad alta.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1133 | External Remote Services | Initial Access |
| T1046 | Network Service Discovery | Discovery |

## Salida

Persistir con `argos_memory_save`. `evidence` debe incluir el puerto,
el servicio identificado (banner si `lan.banner_grab` lo capturó), y la
regla de security group si se dispone de ella. `cwe: "CWE-284"` para
exposición de servicio, o `CWE-306` (Missing Authentication) si además se
confirma ausencia de auth en el servicio expuesto.
