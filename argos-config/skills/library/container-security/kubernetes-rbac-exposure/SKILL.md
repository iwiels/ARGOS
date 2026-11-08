---
name: "kubernetes-rbac-exposure"
description: "Audita manifiestos RBAC de Kubernetes (Role, ClusterRole, RoleBinding) entregados por el cliente en busca de permisos excesivos y exposición del API server."
domain: cybersecurity
subdomain: container-security
tags: ["kubernetes", "rbac", "cluster-admin", "api-server", "k8s", "privilege-escalation"]
mitre_attack: ["T1610", "T1078.004"]
nist_csf: ["PR.AA-05", "PR.IR-01"]
source_adapted_from: "auditing-kubernetes-rbac-privilege-escalation / auditing-kubernetes-cluster-rbac (Anthropic-Cybersecurity-Skills, Apache-2.0) — consolidadas, acotadas a revisión de manifiestos sin `kubectl` contra el cluster real del cliente."
---

# Skill: Exposición RBAC en Kubernetes

Revisión de manifiestos RBAC (`Role`, `ClusterRole`, `RoleBinding`,
`ClusterRoleBinding`) y, cuando aplica, verificación externa del API server
con `lan.port_scan`/`web.probe`. No ejecuta `kubectl` contra el cluster del
cliente — eso requeriría credenciales que Argos no debe manejar en una
auditoría de caja negra.

## Cuándo usar esta skill

- El repositorio en scope contiene manifiestos YAML de Kubernetes con
  `kind: Role`, `ClusterRole`, `RoleBinding` o `ClusterRoleBinding`.
- El scope de red incluye el puerto del API server (`6443` por defecto) o
  del kubelet (`10250`).

## Alcance y límites

Sin acceso al cluster real, el análisis de manifiestos es la fuente de
evidencia principal. La verificación de exposición del API server sí es
externa y legítima (una petición HTTP sin autenticación al endpoint público,
no un ataque activo).

## Procedimiento

1. **Buscar bindings a `cluster-admin`.** Cualquier `ClusterRoleBinding` que
   asigne el `ClusterRole` predefinido `cluster-admin` a un `ServiceAccount`
   de una aplicación (no a un operador humano/administrador) es
   sobre-privilegio casi garantizado — `cluster-admin` otorga control total
   del cluster.

2. **Detectar wildcards en reglas de `Role`/`ClusterRole`:**
   - `resources: ["*"]` junto a `verbs: ["*"]` — equivalente funcional a
     `cluster-admin` aunque no use ese nombre.
   - Permisos sobre el recurso `secrets` con verbo `get`/`list` en un
     `ClusterRole` de amplio alcance — permite leer todos los secretos del
     namespace/cluster, incluyendo credenciales de otras aplicaciones.
   - Permiso sobre `pods/exec` — equivale a ejecución de comandos arbitrarios
     en cualquier pod que el rol alcance.

3. **Verificar exposición externa del API server.** `web.probe` o
   `lan.port_scan` sobre el puerto 6443: una respuesta que no exige
   autenticación mTLS/token, o que expone endpoints de `/api`/`/version` sin
   restricción de red, indica el API server accesible desde fuera del
   cluster — sumamente crítico si además hay RBAC débil.

4. **Revisar `automountServiceAccountToken`.** Si un `Deployment`/`Pod` no
   desactiva explícitamente el montaje automático del token del
   ServiceAccount (`automountServiceAccountToken: false`) y ese
   ServiceAccount tiene permisos amplios, cualquier compromiso del pod
   (p. ej. vía una vulnerabilidad de la aplicación que corre dentro) hereda
   esos permisos automáticamente.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1610 | Deploy Container | Execution |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access, Persistence, Privilege Escalation |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-269"`. `evidence` debe
citar el manifiesto exacto (nombre del binding, del rol, namespace) o la
respuesta HTTP del API server expuesto. `severity: "critical"` para
`cluster-admin` en ServiceAccount de aplicación o API server sin
autenticación.
