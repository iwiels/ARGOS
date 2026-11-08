# Wordlists de `auditoria-web`

## Qué hay acá

`common.txt` es el **fallback offline** de Argos: la lista de contenido web
de SecLists (`Discovery/Web-Content/common.txt`, tag `2026.1`, 4.751
entradas) que viaja con el repo. Es byte-idéntica al archivo publicado
upstream, así que su SHA-256 coincide con el pin del registry.

**No borres ni edites `common.txt`**: sin red —o si una descarga falla— las
tools de fuzzing caen a esta lista y lo declaran en el resultado con
`wordlist_source: "bundled"`.

El fallback es **genérico** (contenido web). La única excepción es el
perfil `params`, que usa la lista embebida de nombres de parámetro
(45 entradas) porque una lista de rutas no sirve para probar parámetros.

## Wordlists grandes (descarga on-demand)

El resto de las wordlists no viven en el repo: se descargan bajo demanda
desde [SecLists](https://github.com/danielmiessler/SecLists) en el tag
pinned `2026.1`, se cachean en `<toolsDir>/wordlists/` y se **verifican por
SHA-256** antes de usarse. Si el digest no coincide, la descarga se
descarta y el scan cae al fallback bundled (nunca se usa una lista
manipulada).

El catálogo completo se puede consultar en runtime con la tool
`web.wordlists` (nombre, tipo, entradas, tamaño y estado de cache).

| Wordlist | Origen upstream | Entradas | Uso |
|---|---|---|---|
| `raft-large-words` | `Discovery/Web-Content/raft-large-words.txt` | 119.600 | directorios (perfil `dirs`, default de `web.fuzz`) |
| `raft-small-words` | `Discovery/Web-Content/raft-small-words.txt` | 43.007 | fuzzing rápido (perfil `small`) |
| `common` | `Discovery/Web-Content/common.txt` | 4.751 | lista corta genérica |
| `api-endpoints` | `Discovery/Web-Content/api/api-endpoints.txt` | 285 | endpoints de API (perfil `api`) |
| `param-names` | `Discovery/Web-Content/burp-parameter-names.txt` | 6.453 | nombres de parámetro (perfil `params`, default de `web.params`) |
| `dns` | `Discovery/DNS/namelist.txt` | 151.265 | hosts / vhosts (perfil `hosts`, `dns`) |
| `bypass` | `Fuzzing/login_bypass.txt` | 896 | bypass de login (perfil `bypass`) |

## Perfiles

Los perfiles son alias que las tools aceptan en el parámetro `wordlist`:

| Perfil | Resuelve a |
|---|---|
| `dirs`, `dir`, `paths`, `big`, `large` | `raft-large-words` |
| `small`, `fast` | `raft-small-words` |
| `common` | `common` |
| `api`, `endpoints` | `api-endpoints` |
| `params`, `param` | `param-names` |
| `dns`, `hosts` | `dns` |
| `bypass` | `bypass` |

El nombre concreto de la wordlist también se acepta (`wordlist:
"raft-large-words"`).

## Cache y TTL

- Directorio: `<toolsDir>/wordlists/` (`ARGOS_TOOLS_DIR`, por defecto
  `~/.argos/tools`).
- Nombre del archivo: `<name>-<version>.txt`, así un pin nuevo nunca
  pisa al anterior.
- TTL por defecto: 30 días (`ARGOS_WORDLIST_TTL_DAYS`). Pasado el TTL el
  archivo se **re-verifica** contra el SHA-256 pinneado; sólo se
  re-descarga si el digest ya no coincide o si el archivo falta.

## Ejemplos

```
argos-web_web.fuzz({ target: "https://example.com", mode: "dir" })              # usa raft-large-words
argos-web_web.fuzz({ target: "https://example.com", mode: "dir", wordlist: "small" })
argos-web_web.fuzz({ target: "https://example.com", mode: "vhost", wordlist: "hosts" })
argos-web_web.params({ target: "https://example.com/search" })                   # usa param-names
argos-web_web.wordlists({ kind: "dirs" })
```

El resultado de `web.fuzz` y `web.params` declara siempre la wordlist
usada: `wordlist`, `wordlist_source` (`downloaded` | `cached` | `bundled`)
y `wordlist_entries`.
