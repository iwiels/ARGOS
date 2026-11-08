# Playbooks de vulnerabilidades — Argos

Conocimiento ofensivo curado que los agentes cargan bajo demanda
(mediante la tool `load_skill`) antes de auditar una clase específica.

## Formato obligatorio

```markdown
---
name: <id-kebab-case>
titulo: <nombre legible>
severidad_default: critical|high|medium|low
categoria_owasp: <ID OWASP Top 10 2021, ej. A01>
---

# <Título>

## Superficie
Dónde aparece esta clase de falla y qué tipos de sistema la sufren.

## Objetivos de alto valor
Qué mirar PRIMERO ordenado por probabilidad×impacto.

## Técnicas y variaciones
Cómo probarla, con variaciones por framework/patrón comunes en el ecosistema
LATAM (PHP heredado, .NET corporativo, stacks JS modernos).

## Knobs de bypass
Parámetros/cabeceras/patrones que suelen desactivar controles mal aplicados.

## Criterio de PoC (obligatorio)
Qué evidencia mínima debe ejecutar el agente para marcar el hallazgo como
`validated`. Sin esto el hallazgo queda `candidate` y NO entra al reporte.
El script + output del PoC se registran en la cadena de evidencia.
```

## Reglas

1. 100% original — prohibido traducir playbooks de terceros.
2. Español técnico; nombres de parámetros/headers en inglés tal como aparecen en requests reales.
3. Máximo ~120 líneas por playbook: denso, sin relleno.
4. Todo playbook referencia su criterio de PoC ejecutable.
