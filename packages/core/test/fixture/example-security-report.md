# Reporte de Auditoria de Seguridad — example-university.edu (Facultad de Ejemplo)

**Target:** https://www.example-university.edu/
**Session:** example-university-2026-08-14
**Run ID:** 20260814-000000-https---www.example-university.
**Fecha:** 2026-08-14 | **Metodologia:** OWASP Testing Guide v4.2 / PTES / OSSTMM 3
**Autorizacion:** explicita del usuario 2026-08-14 (autorizacion-explicita-usuario-2026-08-14)

---

## 1. Resumen ejecutivo

1. **El sitio institucional esta activamente comprometido**: se sirven +30 enlaces ocultos a dominios de spam ilegales inyectados a nivel de archivo del template CMS en **todas las paginas** — se requiere respuesta a incidentes inmediata (P0), no un simple cleanup.
2. **Toda la plataforma esta fuera de soporte**: CMS 3.10.8 (EOL), PHP 8.1.34 (EOL), Apache 2.4.52 (CVEs criticos sin parche, CVE-2024-38476 CVSS 9.8) e IIS 8.0/Windows Server 2012 (EOL) — cada componente EOL es una puerta de re-entrada y hace **probable la reinfeccion post-limpieza** si no se actualiza primero.
3. El **ERP academico** procesa datos de alumnos sobre infraestructura obsoleta, con login sin CSRF ni rate-limit, y los formularios capturan PII sin consentimiento — **incumplimiento de la ley de proteccion de datos aplicable**.
4. Se documentan exposiciones evitables (phpinfo publico, directorios sensibles, configs de desarrollo), superficie amplia sin inventario (15 subdominios) y DNS sin hardening.
5. **La prioridad absoluta es contener el compromiso, preservar evidencia forense y erradicar el backdoor antes de cualquier otra accion**; en paralelo, aislar/parchear el stack EOL y segmentar el ERP de la DMZ web.

## 2. Hallazgos consolidados (18 unicos a partir de 27 persistidos)

| ID | Severidad | Titulo | CWE | CVE | Estado | Vector |
|----|-----------|--------|-----|-----|--------|--------|
| F-01 | CRITICO | Compromiso activo del CMS — SEO/spam inyectado | CWE-506 | — | validated | templates/example/index.php → todas las paginas |
| F-02 | ALTO | CMS 3.10.8 EOL (CVEs sin parche) | CWE-1104 | CVE-2024-40743/40748/40749 | validated | /administrator, CMS |
| F-03 | ALTO | Apache 2.4.52: 11+ CVEs remotos sin auth | CWE-1104 | CVE-2024-38476 (9.8), CVE-2022-22720, CVE-2023-25690 | validated | Virtualhost completo |
| F-04 | ALTO | PHP 8.1.34 EOL + IIS 8.0/Win2012 EOL | CWE-1104 | — | validated | Stack + /WebAlumno /WebProfesor |
| F-05 | ALTO | Incumplimiento de ley de proteccion de datos (PII) | CWE-359 | — | suspected* | Formularios + ERP |
| F-06 | MEDIO | phpinfo() publico sin sandbox (open_basedir/disable_functions vacios) | CWE-200 | — | validated | /info.php |
| F-07 | MEDIO | Login ERP sin CSRF, rate-limit, HSTS | CWE-522 | — | validated | /WebAlumno/Alumno/LogOn |
| F-08 | MEDIO | Directorios sensibles expuestos | CWE-538 | — | observed | /administrator, /pruebas, /2022 |
| F-09 | MEDIO | 15 subdominios sin inventario | CWE-200 | — | observed | zona example-university.edu |
| F-10 | MEDIO | Apps ASP legacy en wayback (superficie SQLi historica) | CWE-1104 | — | observed | raiz legacy .asp |
| F-11 | MEDIO | DNS hardening incompleto (SPF softfail, sin DNSSEC/CAA) | CWE-16 | — | validated | zona DNS |
| F-12 | MEDIO | Sinks DOM XSS en JS | CWE-79 | — | suspected | /workshop/, contacto |
| F-13 | BAJO | Encuestas: configs de desarrollo expuestas | CWE-538 | CVE-2020-15081 | validated | encuestas.example-university.edu |
| F-14 | BAJO | Cabeceras de seguridad ausentes | CWE-693 | — | validated | raiz, todo el dominio |
| F-15 | BAJO | /2022/ responde HTTP 500 | CWE-388 | — | validated | /2022/ |
| F-16 | BAJO | Extensiones CMS desactualizadas | CWE-1104 | — | validated | com_slideshowck, com_jce |
| F-17 | INFO | Divulgacion de version de servidor | CWE-200 | — | validated | header Server |
| F-18 | INFO | WAF bloquea payloads SQLi (control mitigante) | CWE-693 | — | validated | /workshop/ id_work |

## 3. Analisis de riesgo del top

| ID | CVSS v3.1 | Justificacion |
|----|-----------|---------------|
| F-01 | 10.0 | Sitio publico sirviendo contenido de spam; SEO poisoning; phishing; pivote potencial al ERP con PII (misma DMZ); persistencia en archivo de template → reinfeccion probable |
| F-03 | 9.8 | CVE-2024-38476 Apache core sin auth; smuggling habilita bypass WAF |
| F-02 | 9.1 | CVE-2024-40749 ACL violation; rama EOL sin parche oficial |
| F-05 | legal | Sancion regulatoria aplicable |

**Tesis de compromiso (F-01):** (1) CMS/extensiones desactualizadas; (2) credenciales de /administrator (sin 2FA); (3) archivos de template con acceso previo. Bloque identico en 3 paginas fuera del wrapper CMS → inyeccion en archivo de template (no en BD). ERP IIS es stack separado: no comprometido por esta via, pero misma DMZ → tratar como potencialmente alcanzado.

## 4. Hoja de ruta de remediacion

### P0 — IR inmediato (24-72 h) · F-01
1. Contencion: sitio en mantenimiento; bloquear /administrator por IP; rotar TODAS las credenciales.
2. Evidencia: snapshot filesystem + dump DB ANTES de limpiar.
3. Erradicacion: restaurar backup limpio; limpiar template; ACTUALIZAR CMS + extensiones en el mismo acto.

### P1 — Reduccion de superficie (1-2 semanas) · F-02 a F-08
- Migrar/aislar CMS a version soportada; parchear Apache y PHP.

### P2 — Programa (1-3 meses) · F-09 a F-18
- Inventario y ciclo de parcheo formalizado; hardening DNS; cumplimiento normativo.

## 5. Metricas del engagement

| Severidad | Cantidad |
|-----------|----------|
| CRITICO | 1 |
| ALTO | 4 |
| MEDIO | 7 |
| BAJO | 4 |
| INFO | 2 |
| **Total** | **18** |

---
*Generado por Argos Security Audit Team — security-report · Fixture anonimizada para tests, basada en la estructura real de un reporte de auditoria.*
