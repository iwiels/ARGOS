# Schemas de validación

Schemas oficiales vendorizados para que los tests de export validen contra
la fuente de verdad y no contra una copia de la especificación.

| Archivo | Origen | Licencia |
| :--- | :--- | :--- |
| `sarif-schema-2.1.0.json` | OASIS SARIF v2.1.0 (vía [SchemaStore](https://www.schemastore.org/sarif-2.1.0.json)) | OASIS IPR Policy / BSD-3 |
| `bom-1.5.schema.json` | [CycloneDX specification](https://github.com/CycloneDX/specification) `schema/bom-1.5.schema.json` | Apache-2.0 |

Se vendorizan (en vez de descargarse en cada corrida) para que la validación
sea determinista y funcione sin red — que es lo que exige un gate de CI.

El validador que los usa está en `packages/core/test/lib/json-schema.ts`.
