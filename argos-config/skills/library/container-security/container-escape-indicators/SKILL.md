---
name: "container-escape-indicators"
description: "Identifica configuración de contenedor (modo privilegiado, montajes del host, capacidades excesivas) que habilitaría un escape al host, a partir de manifiestos entregados por el cliente."
domain: cybersecurity
subdomain: container-security
tags: ["container", "container-escape", "privileged-container", "docker-socket", "host-mount", "capabilities"]
mitre_attack: ["T1611", "T1610"]
nist_csf: ["PR.PS-01", "PR.IR-01"]
source_adapted_from: "detecting-container-escape-attempts / detecting-container-escape-with-falco-rules (Anthropic-Cybersecurity-Skills, Apache-2.0) — reescrita como revisión de configuración estática (no requiere Falco desplegado en el cluster del cliente)."
---

# Skill: Indicadores de escape de contenedor

A diferencia de la skill original (que asume Falco corriendo en el cluster
del cliente para detección en runtime), esta versión identifica la
configuración que **habilitaría** un escape revisando manifiestos —
apropiado para una auditoría donde Argos no tiene agentes desplegados
en la infraestructura del cliente.

## Cuándo usar esta skill

- Manifiestos de Kubernetes (`Pod`, `Deployment`, `DaemonSet`) o
  `docker-compose.yml` están en el alcance del engagement.
- El cliente pregunta específicamente por riesgo de "pivote desde contenedor
  a host".

## Procedimiento

1. **Modo privilegiado.** `securityContext.privileged: true` (Kubernetes) o
   `privileged: true` (docker-compose) elimina el aislamiento de namespaces y
   cgroups casi por completo — es la señal más grave por sí sola, sin
   necesitar ninguna otra condición.

2. **Montaje del socket de Docker.** `-v /var/run/docker.sock:/var/run/docker.sock`
   dentro de un contenedor le da control total sobre el daemon Docker del
   host — equivalente a acceso root al host, con independencia de cualquier
   otra restricción del contenedor.

3. **Montajes de rutas sensibles del host.** `hostPath` (Kubernetes) o
   volúmenes bind que apunten a `/`, `/etc`, `/proc`, `/var/run`, o al
   propio directorio de contenedores de Docker/containerd — cualquiera de
   estos permite lectura/escritura directa sobre el sistema de archivos del
   host desde dentro del contenedor.

4. **Capacidades Linux añadidas explícitamente.** `SYS_ADMIN`, `SYS_PTRACE`,
   `SYS_MODULE`, `DAC_OVERRIDE` añadidas vía `securityContext.capabilities.add`
   o `--cap-add` — cada una habilita una clase distinta de escape conocida
   (montaje de filesystems, inyección en otros procesos, carga de módulos
   del kernel, bypass de permisos de archivo respectivamente). Documentar
   cuál capacidad específica se encontró, no agrupar como "capabilities
   excesivas" genérico.

5. **`hostNetwork` / `hostPID` / `hostIPC` en `true`.** Comparten el
   namespace de red, procesos o IPC del host respectivamente — un contenedor
   con `hostPID: true` puede ver y potencialmente señalizar procesos del
   host, incluyendo terminarlos.

6. **Correlacionar con el propósito declarado del workload.** Un contenedor
   de monitoreo/logging que necesita leer métricas del host puede
   legítimamente requerir algún `hostPath` acotado — el hallazgo es cuando
   el privilegio otorgado excede lo que el propósito funcional justifica.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1611 | Escape to Host | Privilege Escalation, Defense Evasion |
| T1610 | Deploy Container | Execution |

## Salida

Persistir con `argos_memory_save`, `severity: "critical"` para modo
privilegiado o montaje del socket Docker, `severity: "high"` para
capacidades individuales o hostPath sensible. `cwe: "CWE-250"`. `evidence`
debe citar el fragmento exacto del manifiesto (nombre del workload, campo,
valor).
