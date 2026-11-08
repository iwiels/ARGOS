// Package env resuelve las variables ARGOS_* de los binarios de seguridad.
package env

import (
	"os"
	"strings"
)

// Get devuelve el valor de la variable name.
func Get(name string) string {
	return os.Getenv(name)
}

const (
	// OASTDomainEnv es el dominio OAST que el operador configura. Apunta a
	// la infraestructura propia de la organización (un interactsh-server propio
	// o un dominio que resuelva contra el host del auditor).
	OASTDomainEnv = "ARGOS_OAST_DOMAIN"
	// OASTExternalEnv habilita explícitamente un proveedor OAST de terceros.
	// Sin este opt-in, ningún callback sale de la máquina del auditor.
	OASTExternalEnv = "ARGOS_OAST_EXTERNAL"
	// OASTBindEnv es la dirección donde escucha el colector OAST propio.
	OASTBindEnv = "ARGOS_OAST_BIND"
)

// OASTDomain devuelve el dominio OAST configurado por el operador, o "".
func OASTDomain() string {
	return strings.TrimSpace(Get(OASTDomainEnv))
}

// OASTExternal indica si el operador habilitó explícitamente un proveedor
// OAST externo. El valor exacto "1" es el único que activa el modo externo.
func OASTExternal() bool {
	return strings.TrimSpace(Get(OASTExternalEnv)) == "1"
}

// OASTBind devuelve la dirección de escucha del colector OAST propio, o ""
// para usar el bind de loopback por defecto.
func OASTBind() string {
	return strings.TrimSpace(Get(OASTBindEnv))
}
