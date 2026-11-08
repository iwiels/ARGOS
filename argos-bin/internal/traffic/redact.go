package traffic

import (
	"net/url"
	"regexp"
	"strings"
)

// Redacción de credenciales.
//
// El store de tráfico vive en disco y sobrevive al engagement: una cabecera
// `Authorization` guardada en claro convertiría el store en un repositorio de
// credenciales. El criterio es el mismo que aplica el bundle de logs de
// Argos Desktop (packages/desktop/src/main/redact.ts): tokens en query
// strings, esquemas de autenticación, campos JSON de tipo password/token y
// basic-auth embebido en la URL.
//
// Lo que NO se redacta es el body de la respuesta: es la evidencia que el
// auditor vino a buscar, y tapar un password filtrado por el servidor
// justamente taparía el hallazgo.

var (
	// (bearer\s+)[A-Za-z0-9._~+/=-]{8,}
	bearerPattern = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)
	// (x-api-key\s*[:=]\s*)[^\s,"'}\]]+
	apiKeyPattern = regexp.MustCompile(`(?i)(x-api-key\s*[:=]\s*)[^\s,"'}\]]+`)
	// (authorization\s*[:=]\s*["']?)[^"'\s,}]+
	authorizationPattern = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*["']?)[^"'\s,}]+`)
	// ("(?:password|api[_-]?key|secret|token)"\s*:\s*")[^"]+
	jsonSecretPattern = regexp.MustCompile(`(?i)("(?:password|api[_-]?key|secret|token)"\s*:\s*")[^"]+`)
	// (\w[\w.-]*:\/\/[^/\s:@"]+:)([^@\s/"]+@)
	basicAuthPattern = regexp.MustCompile(`(\w[\w.-]*:\/\/[^/\s:@"]+:)([^@\s/"]+@)`)
	// (auth_token=)[^&\s"')]+
	authTokenPattern = regexp.MustCompile(`(?i)(auth_token=)[^&\s"')]+`)
	// ((?:password|passwd|token|access_token|api[_-]?key|secret)=)[^&\s"']+
	formSecretPattern = regexp.MustCompile(`(?i)((?:password|passwd|token|access_token|api[_-]?key|secret)=)[^&\s"']+`)
)

// sensitiveHeaders nunca se guardan en claro.
var sensitiveHeaders = map[string]bool{
	"authorization": true,
	"cookie":        true,
	"set-cookie":    true,
	"x-api-key":     true,
}

// secretQueryParams son los parámetros de query que llevan credenciales.
var secretQueryParams = map[string]bool{
	"auth_token":   true,
	"token":        true,
	"access_token": true,
	"api_key":      true,
	"apikey":       true,
	"password":     true,
	"passwd":       true,
	"secret":       true,
}

// RedactHeaders returns a copy of the headers with the credential-bearing
// ones masked.
//
// Se conserva el esquema ("Bearer ***") y los nombres de las cookies: el
// auditor necesita saber qué credencial se usó, no cuál era.
func RedactHeaders(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for name, values := range headers {
		if !sensitiveHeaders[strings.ToLower(strings.TrimSpace(name))] {
			out[name] = append([]string(nil), values...)
			continue
		}
		masked := make([]string, 0, len(values))
		for _, value := range values {
			masked = append(masked, maskHeaderValue(name, value))
		}
		out[name] = masked
	}
	return out
}

// maskHeaderValue masks the value of a sensitive header.
func maskHeaderValue(name, value string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization":
		// "Bearer abc.def" -> "Bearer ***": el esquema dice qué credencial
		// se usó y no filtra el secreto.
		if scheme, _, ok := strings.Cut(value, " "); ok && strings.TrimSpace(scheme) != "" {
			return strings.TrimSpace(scheme) + " ***"
		}
		return "***"
	case "cookie", "set-cookie":
		return maskCookies(value)
	default:
		return "***"
	}
}

// maskCookies keeps the cookie names and drops the values.
func maskCookies(value string) string {
	parts := strings.Split(value, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		name, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			out = append(out, "***")
			continue
		}
		out = append(out, strings.TrimSpace(name)+"=***")
	}
	if len(out) == 0 {
		return "***"
	}
	return strings.Join(out, "; ")
}

// RedactURL masks the credentials embedded in a URL.
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return basicAuthPattern.ReplaceAllString(raw, "$1***@")
	}
	if parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			parsed.User = url.UserPassword(parsed.User.Username(), "***")
		}
	}
	if parsed.RawQuery != "" {
		query := parsed.Query()
		changed := false
		for key := range query {
			if secretQueryParams[strings.ToLower(key)] {
				query.Set(key, "***")
				changed = true
			}
		}
		if changed {
			parsed.RawQuery = query.Encode()
		}
	}
	return basicAuthPattern.ReplaceAllString(parsed.String(), "$1***@")
}

// RedactRequestBody masks the credential fields of a request body.
//
// Solo se aplica al body de la request: es el que lleva las credenciales que
// el auditor manda. El body de la respuesta es evidencia y se conserva tal
// cual.
func RedactRequestBody(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	text := string(body)
	redacted := jsonSecretPattern.ReplaceAllString(text, "$1[REDACTED]")
	redacted = formSecretPattern.ReplaceAllString(redacted, "$1[REDACTED]")
	redacted = bearerPattern.ReplaceAllString(redacted, "$1[REDACTED]")
	redacted = apiKeyPattern.ReplaceAllString(redacted, "$1[REDACTED]")
	redacted = authorizationPattern.ReplaceAllString(redacted, "$1[REDACTED]")
	redacted = authTokenPattern.ReplaceAllString(redacted, "$1[REDACTED]")
	redacted = basicAuthPattern.ReplaceAllString(redacted, "$1***@")
	return []byte(redacted)
}
