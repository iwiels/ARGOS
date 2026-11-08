---
name: "container-image-hardening"
description: "Audita Dockerfiles y manifiestos de imagen entregados por el cliente en busca de root innecesario, secretos horneados en capas, y bases sin fijar versión."
domain: cybersecurity
subdomain: container-security
tags: ["container", "docker", "dockerfile", "image-hardening", "root-user", "baked-secret", "sbom"]
mitre_attack: ["T1610", "T1552"]
nist_csf: ["PR.PS-01", "PR.PS-02"]
source_adapted_from: "analyzing-sbom-for-supply-chain-vulnerabilities (Anthropic-Cybersecurity-Skills, Apache-2.0) — acotada a revisión estática de Dockerfile/manifiesto, sin asumir trivy/grype instalados."
---

# Skill: Hardening de imágenes de contenedor

Revisión estática de `Dockerfile` y manifiestos de build que el cliente
entrega o que aparecen en el repositorio en scope de `security-code`. No
requiere un scanner de imágenes instalado (trivy/grype) — los patrones más
costosos son detectables leyendo el Dockerfile directamente.

## Cuándo usar esta skill

- El repositorio en scope contiene `Dockerfile`, `docker-compose.yml`, o
  manifiestos de build (`.dockerignore` ausente es también señal).
- El cliente declara contenedores como parte de su infraestructura y
  comparte el Dockerfile como insumo.

## Alcance y límites

Es revisión de código de infraestructura, no un scan de vulnerabilidades del
sistema operativo dentro de la imagen (eso requeriría trivy/grype, que
Argos no envuelve hoy — ver backlog en `README.md` de esta biblioteca).
El foco es en patrones de configuración insegura visibles en el propio
Dockerfile.

## Procedimiento

1. **Usuario del proceso.** Buscar ausencia de una instrucción `USER` no-root
   antes del `CMD`/`ENTRYPOINT` final. Sin `USER`, el contenedor corre como
   `root` por defecto — si además el contenedor tiene `--privileged` o
   monta el socket de Docker, el impacto de un compromiso escala
   directamente a host.

2. **Secretos horneados en capas.** Buscar `ARG`/`ENV` con nombres que
   sugieran secretos (`API_KEY`, `PASSWORD`, `TOKEN`, `PRIVATE_KEY`) con
   valor literal en el Dockerfile, o comandos `RUN` que descarguen/copien
   archivos de credenciales (`COPY .env .`, `COPY id_rsa .`). Importante:
   un `ARG` con secreto **persiste en el historial de capas de la imagen**
   aunque se borre en una capa posterior — el Dockerfile debe usar
   `--mount=type=secret` (BuildKit) o multi-stage build para evitarlo, y su
   ausencia ante un secreto detectado es en sí un hallazgo.

3. **Imagen base sin fijar.** `FROM node:latest` o `FROM ubuntu` sin tag de
   versión específico es un hallazgo de superficie de ataque (build no
   reproducible, actualizaciones no auditadas entre builds) — CWE-1104
   (Use of Unmaintained Third Party Components) aplica por analogía.

4. **Exposición innecesaria de puertos/capacidades.** `EXPOSE` de puertos de
   depuración o gestión que no deberían llegar a producción; capacidades
   Linux añadidas explícitamente (`--cap-add=SYS_ADMIN` en el compose) sin
   justificación funcional clara.

5. **Multi-stage build ausente cuando correspondería.** Si el Dockerfile
   instala herramientas de compilación (`build-essential`, `gcc`,
   dependencias de dev) y las deja en la imagen final en vez de usar
   multi-stage, aumenta innecesariamente la superficie de la imagen —
   señalar como mejora, severidad baja salvo que las herramientas dejadas
   sean explotables (shells, compiladores en un contenedor que no debería
   tenerlos).

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1610 | Deploy Container | Execution |
| T1552 | Unsecured Credentials | Credential Access |

## Salida

Persistir con `argos_memory_save`, citando la línea exacta del
Dockerfile en `evidence`. `cwe: "CWE-250"` (Execution with Unnecessary
Privileges) para hallazgos de usuario root, `CWE-798` para secretos
horneados. `needs_followup_by: ["security-code"]` si el secreto detectado
está también presente en el repositorio fuente (no solo en la imagen).
