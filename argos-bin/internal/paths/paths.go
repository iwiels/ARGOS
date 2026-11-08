// Package paths resuelve las rutas de datos por defecto de los binarios de
// seguridad.
package paths

import (
	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
)

// MemoryDirEnv sobreescribe el directorio de memoria para todos los binarios.
// El backend (packages/core) lee la misma variable, así que ambos lados
// comparten el store aunque no se pase --memory-dir.
const MemoryDirEnv = "ARGOS_MEMORY_DIR"

// DefaultMemoryDir es la ruta canónica del store de memoria compartida.
func DefaultMemoryDir(home string) string {
	return home + "/.argos/memory"
}

// ResolveMemoryDir devuelve el directorio de memoria a usar.
func ResolveMemoryDir(home string) string {
	if override := env.Get(MemoryDirEnv); override != "" {
		return override
	}
	return DefaultMemoryDir(home)
}
