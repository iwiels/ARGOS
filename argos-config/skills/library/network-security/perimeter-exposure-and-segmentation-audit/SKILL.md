---
name: "perimeter-exposure-and-segmentation-audit"
description: "Evalúa servicios de gestión expuestos (SSH, RDP, SMB, bases de datos) y contigüidad de bloques /24 para detectar hosts secundarios/staging compartiendo segmento sin aislar — complementa cloud-network-exposure para infraestructura no-cloud."
domain: cybersecurity
subdomain: network-security
tags: ["network", "perimeter", "segmentation", "exposed-management-port", "slash-24"]
mitre_attack: ["T1046", "T1133", "T1021"]
nist_csf: ["PR.AA-05", "PR.IR-01"]
iso_27001: ["A.8.20", "A.8.21", "A.8.22"]
source_adapted_from: "network-exposure-audit (adaptación local, consolidada desde Anthropic-Cybersecurity-Skills, Apache-2.0). Distinta de cloud-network-exposure de esta misma biblioteca: aquella correlaciona con security groups cloud, esta aplica a cualquier infraestructura perimetral (on-prem o cloud sin ese contexto disponible)."
---

# Skill: Exposición perimetral y segmentación de red

Dos análisis distintos sobre la misma salida de `lan.port_scan`/
`lan.host_discovery`: qué servicios de gestión están expuestos, y si hosts
que deberían estar aislados (staging, portales internos) comparten bloque de
red pública con la infraestructura de producción.

## Cuándo usar esta skill

- El scope de red incluye IPs públicas de la organización, con o sin
  contexto cloud disponible (a diferencia de `cloud-network-exposure`, que
  requiere identificar el proveedor cloud específico).

## Procedimiento

1. **Clasificar puertos de gestión por severidad de exposición directa:**
   - **Crítico**: RDP (3389) o SMB (445) expuestos directamente a internet
     sin VPN — son los vectores de explotación masiva más buscados
     (ransomware operators escanean activamente por estos).
   - **Alto**: SSH (22) con autenticación por password (no solo por llave)
     expuesto sin rate-limiting visible (repetir el patrón de
     `rate-limiting-and-throttling` de esta biblioteca contra el propio
     servicio SSH si el engagement lo permite).
   - **Medio**: bases de datos (3306, 5432, 1433, 27017, 6379) expuestas —
     coincide con `cloud-storage-exposure`/`cloud-network-exposure` cuando
     el contexto es cloud; aquí aplica igual sin necesidad de confirmar el
     proveedor.
   - Protocolos inseguros: HTTP plano sin redirección forzada a HTTPS,
     SNMP v1/v2c con community string por defecto (`public`/`private`)
     — ambos son hallazgos de bajo esfuerzo de detección y alto valor
     informativo para un atacante.

2. **Analizar contigüidad en el bloque `/24`.** Si el host principal en
   scope es, por ejemplo, `203.0.113.50`, escanear el rango
   `203.0.113.0/24` completo (dentro del alcance autorizado del engagement)
   con `lan.host_discovery` para identificar hosts adicionales de la misma
   organización compartiendo el segmento. El patrón a buscar: servidores de
   staging/desarrollo, paneles de administración de terceros, o
   aplicaciones secundarias sin el mismo nivel de hardening que el sistema
   principal — comparten exposición de red aunque no compartan criticidad.

3. **Correlacionar con la topología ya construida.** Si `lan.build_topology`
   ya mapeó la red, usar esa salida en vez de re-escanear — el objetivo es
   identificar cuáles de los hosts topológicamente cercanos NO deberían
   estar en el mismo segmento que producción.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1046 | Network Service Discovery | Discovery |
| T1133 | External Remote Services | Initial Access |
| T1021 | Remote Services | Lateral Movement |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-284"` para exposición de
servicio, `CWE-306` si además se confirma ausencia de autenticación.
`severity: "critical"` para RDP/SMB expuestos sin VPN, `"medium"` para
hosts secundarios contiguos sin aislamiento — la severidad de un host
staging expuesto depende de qué tan reutilizables sean sus credenciales
contra producción, documentarlo si es verificable sin explotación activa.
