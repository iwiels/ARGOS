---
name: "llm-application-data-exposure"
description: "Audita aplicaciones con LLM en busca de fuga de datos de entrenamiento/RAG, memorización de PII, y exposición de contexto de otros usuarios en la respuesta del modelo."
domain: cybersecurity
subdomain: ai-security
tags: ["ai-security", "llm", "data-exposure", "rag-poisoning", "pii-leakage", "owasp-llm-06"]
mitre_attack: ["T1213", "T1005"]
nist_csf: ["PR.DS-01"]
source_adapted_from: "detecting-data-and-model-poisoning / assessing-vector-and-embedding-weaknesses (Anthropic-Cybersecurity-Skills, Apache-2.0) — acotada a exposición de datos vía la aplicación (caja negra), sin acceso al pipeline de entrenamiento del cliente."
---

# Skill: Exposición de datos en aplicaciones con LLM

Complementa `prompt-injection-in-llm-integrations`: mientras esa skill se
enfoca en manipular el comportamiento del modelo, esta se enfoca en qué
**datos** puede filtrar — de entrenamiento, de la base de conocimiento
(RAG), o de otros usuarios del mismo sistema.

## Cuándo usar esta skill

- La aplicación en scope tiene un LLM que responde preguntas sobre una base
  de conocimiento propia del cliente (RAG: retrieval-augmented generation),
  o que fue fine-tuneado sobre datos del cliente.

## Alcance y límites

Caja negra: se prueba a través de la interfaz de la aplicación, sin acceso
al pipeline de entrenamiento ni a los embeddings/vector store del cliente
(eso requeriría credenciales de infraestructura fuera del alcance típico de
una auditoría de aplicación).

## Procedimiento

1. **Probar fuga de datos de la base de conocimiento (RAG) fuera de
   contexto autorizado.** Si el sistema debería responder solo sobre
   documentos que el usuario actual tiene permitido ver, probar preguntas
   que sondeen la existencia de documentos de otros tenants/usuarios
   ("¿tienes información sobre [nombre de otro cliente/proyecto]?") — una
   respuesta que confirma o cita contenido de fuera del scope autorizado del
   usuario es fuga de datos vía retrieval mal aislado, no un problema del
   modelo en sí sino del filtrado de documentos antes de la generación.

2. **Probar memorización de PII si el modelo fue fine-tuneado.** Consultas
   que sondeen si el modelo puede reproducir datos específicos que
   plausiblemente estaban en su set de fine-tuning (nombres, emails, números
   de documento asociados a contextos muy específicos del negocio del
   cliente) — si el modelo los reproduce verbatim ante una consulta que no
   los proporciona explícitamente, hay memorización de datos de
   entrenamiento.

3. **Revisar si el system prompt contiene datos sensibles.** Complementa el
   punto de extracción de system prompt de la skill de inyección — aquí el
   foco es específicamente si esas instrucciones incluyen ejemplos con datos
   reales de clientes/usuarios (few-shot examples con PII real en vez de
   datos sintéticos), que quedarían expuestos ante cualquier extracción
   exitosa del prompt.

4. **Probar aislamiento de contexto entre sesiones concurrentes.** Si la
   arquitectura del cliente reutiliza instancias/workers del LLM entre
   requests de distintos usuarios (común en implementaciones que no
   gestionan bien el aislamiento de contexto por request), sondear si es
   posible que fragmentos de una conversación de otro usuario aparezcan en
   la respuesta — especialmente bajo carga concurrente.

5. **Revisar logging del lado del proveedor de LLM.** Si la aplicación
   envía datos sensibles del usuario al prompt de un proveedor externo
   (OpenAI, Anthropic, etc.) sin mecanismo de anonimización, y la política
   de retención de datos del proveedor no está alineada con los
   requisitos regulatorios del cliente (GDPR, sector financiero) — esto es
   exactamente la clase de problema que el proxy de pseudonimización de
   Argos existe para prevenir en nuestro propio producto; documentarlo
   como hallazgo de arquitectura si la aplicación del cliente carece de un
   control equivalente.

## Mapeo MITRE ATT&CK

| ID | Técnica | Táctica |
|---|---|---|
| T1213 | Data from Information Repositories | Collection |
| T1005 | Data from Local System | Collection |

## Salida

Persistir con `argos_memory_save`, `cwe: "CWE-200"` (Exposure of
Sensitive Information), `CWE-522` si involucra credenciales específicamente.
`evidence` debe incluir la consulta exacta y el fragmento de respuesta que
confirma la fuga — sin reproducir PII real de terceros en el propio
hallazgo si es evitable; describir el tipo de dato filtrado en su lugar.
