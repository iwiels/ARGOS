---
name: idor
titulo: Referencias de objeto inseguras (IDOR/BOLA)
severidad_default: high
categoria_owasp: A01
---

# IDOR / BOLA — Control de acceso a nivel de objeto

## Superficie

Fallan cuando el servidor confía en un identificador que llega del cliente sin
verificar que ese identificador pertenece al solicitante. Típico en APIs REST,
backends para SPA/móvil, y sistemas multi-tenant con aislamiento débil.

Frecuente en desarrollos donde el frontend "oculta" botones pero el backend no
valida, y en migraciones donde se reutiliza un controlador para varios roles.

## Objetivos de alto valor

1. Endpoints `/api/v1/{recurso}/{id}` numéricos secuenciales (facturas, tickets,
   expedientes, descargas de documentos).
2. Campos `userId`/`cuentaId`/`empresaId` dentro del BODY de requests POST/PUT —
   el equipo suele validar el token pero no la pertenencia del objeto.
3. Descargas de archivos por nombre/hash (`/descargar?file=...`) en sistemas
   documentales (historia clínica, expedientes legales, nóminas).
4. Endpoints internos expuestos: `/api/admin/*` accesibles con token de usuario
   estándar cambiando solo la ruta.
5. Webhooks y callbacks que aceptan `id` externo sin firma.

## Técnicas y variaciones

- **Horizontal**: dos cuentas propias A y B; capturar el id del objeto de A y
  solicitarlo autenticado como B. Éxito = contenido de A.
- **Vertical**: con cuenta de menor privilegio, iterar ids hasta hallar objetos
  de rol superior; comparar códigos de respuesta (200 vs 403 revela existencia).
- **Cross-tenant**: en SaaS multi-tenant, cambiar el slug/subdominio del tenant
  manteniendo el id del recurso.
- **Métodos alternativos**: si `GET /api/factura/123` da 403, probar
  `POST /api/factura/123`, `PATCH`, o versiones `/v2/`, `/internas/`.
- **GraphQL**: sin DataLimiters, consultar `{ facturas { id } }` sin filtro de
  usuario; introspección revela relaciones navegables.
- **Patrón LATAM común**: RUT/CUIT/DNI como clave pública en rutas de perfil —
  enumerar documentos asociados a identificadores públicos conocidos.

## Knobs de bypass

Cabeceras y parámetros que suelen saltarse middlewares mal configurados:
`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`,
`Content-Type: application/json` sobre endpoints que esperan form-data
(y viceversa), sufijos `;.json`/`%00`, doble encoding `%252f`,
mayúsculas/minúsculas en ruta (`/Api/Admin`).

Knobs de expansión que amplían la respuesta más allá del propio objeto:
`fields`, `include`, `expand`, `populate`, `with`, `select`.

## Criterio de PoC

`validated` SOLO si se demuestra acceso cruzado real:

1. Dos cuentas controladas por el auditor (A propietaria, B atacante).
2. Request completo de B leyendo/modificando el objeto de A, con respuesta
   que contenga datos privados de A (no solo 200 vacío ni metadatos públicos).
3. Par de evidencia: request con headers/tokens completos + body de respuesta.

Queda `refuted` si el sistema responde 403/404 consistente para todo objeto
externo incluyendo variantes de método y expansión. Registrar los intentos
como evidencia del refutado (demuestra que el control existe).
