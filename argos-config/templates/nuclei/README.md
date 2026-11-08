# Argos nuclei template packs

Plantillas propias para las clases que el set de la comunidad no cubre bien.
Se suman al set comunitario pineado; no lo reemplazan.

## Estructura

```
templates/nuclei/
  registry.json          catálogo de packs (id, path, enabled, requiresAuth, ...)
  business-logic/        importes y descuentos controlados por el cliente
  idor/                  objetos devueltos sin autorización
  framework/             modo desarrollo y endpoints de diagnóstico
  cicd/                  artefactos de pipeline observables por HTTP
```

`registry.json` es la fuente de verdad del catálogo: `web.templates` lo lee y
`web.scan` lo usa para resolver qué directorios agregar a `-templates`.
Deshabilitar un pack (`"enabled": false`) lo saca del scan por defecto sin
borrar las plantillas; pedirlo por nombre en `web.scan` (`"packs": ["idor"]`)
lo vuelve a habilitar para esa corrida.

## Contrato de metadata

Cada plantilla declara, además de lo que nuclei ya usa:

| Clave | Para qué |
|---|---|
| `argos-pack` | pack al que pertenece; se copia a `evidence.pack` |
| `argos-requires-auth` | si la sonda necesita sesión para ser concluyente |
| `argos-severity-floor` | piso de severidad; nunca baja lo que declare la plantilla |
| `argos-evidence` | qué se espera ver cuando el hallazgo es real |
| `argos-owasp` | categoría OWASP cuando la clasificación de nuclei no la trae |

`parse.go` (Go) copia `argos-pack`, `argos-evidence` y `argos-requires-auth` a
la evidencia del hallazgo y aplica el piso de severidad. La taxonomía
(`cwe-id`, `cvss-metrics`, `cvss-score`) sale de `classification`, así que el
CWE y el CVSS del hallazgo son los de la plantilla, no los que adivine el
modelo.

## Reglas de autoría

1. **Un matcher de contenido, no de status.** Un 200 solo no es un hallazgo:
   toda plantilla exige una palabra, regex o extracción que pruebe la
   condición. Un CDN que responde 200 a todo no debe disparar nada.
2. **Sin lookahead.** nuclei usa RE2; `(?=...)` no compila.
3. **`stop-at-first-match` en sondas con varias rutas** para no reportar el
   mismo problema N veces.
4. **Nada destructivo.** Sin `dos`, sin escrituras, sin descargar artefactos
   gigantes (por eso no hay plantilla de `heapdump`).
5. **La severidad no se infla.** Si la sonda confirma una señal y no una
   explotación, va `medium` o `low` y la descripción lo dice.
6. **`metadata.max-request`** refleja la cantidad de requests de la plantilla.

## Validación

Con nuclei v3 (el binario pineado por Argos):

```bash
nuclei -validate -t argos-config/templates/nuclei -duc -no-color
```

CI corre además `go test ./cmd/web/tools -run 'Pack'`: verifica que el registro
sea coherente, que no haya path traversal y que cada plantilla tenga id, CWE,
CVSS, severidad y matchers.

## Licencia

MIT, la misma del proyecto. Las plantillas son autoría de Argos; no se
redistribuyen plantillas de terceros.
