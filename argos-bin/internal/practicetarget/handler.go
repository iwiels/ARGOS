// Package practicetarget provides a deliberately vulnerable web application
// used ONLY as a local practice target for E2E tests and product demos.
//
// It is intentionally insecure: no security headers, SQL injection in query
// parameters (boolean differential + SQL error markers), reflected XSS, a
// cookie without Secure/HttpOnly, a hidden admin route, an exposed .env, an
// exposed .git directory and a backup file (served under the two spellings a
// fuzzer uses: /backup.zip and /backup).
//
// Since ARG-051 the target also exposes the vulnerability classes the
// benchmark had no coverage for: IDOR/BOLA, CSRF, JWT abuse (alg:none and a
// weak claim audit), blind SSRF, XXE, SSTI, an open redirect, a path
// traversal, a command injection, an unsafe deserialization, GraphQL
// introspection, HTTP request smuggling (through a broken front-end proxy), a
// race condition on a single-use coupon, user enumeration, a missing rate
// limit, an exposed git repository, a permissive CORS policy, missing cookie
// flags, verb tampering, an information disclosure endpoint and a dangling
// subdomain.
//
// Every one of those behaviours is real: the sinks actually reach the file
// system, the shell, the network or the parser. Do NOT expose it beyond
// localhost.
package practicetarget

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Handler returns the practice target's root handler.
func Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", index)
	mux.HandleFunc("/search", search)
	mux.HandleFunc("/item", item)
	mux.HandleFunc("/profile", profile)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/admin/", admin)
	mux.HandleFunc("/api/health", apiHealth)
	mux.HandleFunc("/api/version", apiVersion)
	mux.HandleFunc("/robots.txt", robots)
	mux.HandleFunc("/.env", dotEnv)
	mux.HandleFunc("/backup.zip", backupZip)
	mux.HandleFunc("/backup", backupZip)

	// The vulnerability classes the benchmark measures (ARG-051).
	mux.HandleFunc("/api/item/", apiItem)
	mux.HandleFunc("/api/token", apiToken)
	mux.HandleFunc("/api/transfer", apiTransfer)
	mux.HandleFunc("/api/cors", apiCORS)
	mux.HandleFunc("/api/login", apiLogin)
	mux.HandleFunc("/api/coupon", apiCoupon)
	mux.HandleFunc("/api/deserialize", apiDeserialize)
	mux.HandleFunc("/api/data", apiData)
	mux.HandleFunc("/api/cache", apiCache)
	mux.HandleFunc("/api/xml", apiXML)
	mux.HandleFunc("/openapi.json", openAPI)
	mux.HandleFunc("/fetch", fetch)
	mux.HandleFunc("/render", render)
	mux.HandleFunc("/redirect", redirect)
	mux.HandleFunc("/download", download)
	mux.HandleFunc("/ping", ping)
	mux.HandleFunc("/graphql", graphql)
	mux.HandleFunc("/unicode/", unicodePath)
	mux.HandleFunc("/debug/vars", debugVars)
	mux.HandleFunc("/static/app.js", staticAppJS)
	mux.HandleFunc("/.git/", gitIndex)
	mux.HandleFunc("/.git/HEAD", gitHEAD)
	mux.HandleFunc("/.git/config", gitConfig)

	return mux
}

// commonHeaders sets the fingerprints the tools are expected to detect and,
// deliberately, omits every security header (CSP, HSTS, X-Frame-Options, ...).
func commonHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Server", "ArgosTestServer/1.0")
	h.Set("X-Powered-By", "Go")
	h.Set("X-Generator", "argos-practice-target")
}

func page(title, body string) string {
	return "<!DOCTYPE html><html><head><title>" + title + "</title></head><body>" + body + "</body></html>"
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// The dangling subdomain: the vhost still answers, so the record can be
	// claimed by whoever owns the domain.
	if strings.EqualFold(r.Host, danglingHost) {
		danglingBucket(w, r)
		return
	}
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := "<h1>Argos Practice Target</h1><ul>" +
		"<li><a href=\"/search?q=1\">Búsqueda (SQLi)</a></li>" +
		"<li><a href=\"/item?id=1\">Producto (SQLi numérico)</a></li>" +
		"<li><a href=\"/profile?user=admin\">Perfil (XSS reflejado)</a></li>" +
		"<li><a href=\"/login\">Login (sin CSRF)</a></li>" +
		"<li><a href=\"/api/health\">API health</a></li>" +
		"<li><a href=\"/api/version\">API version</a></li>" +
		"<li><a href=\"/robots.txt\">robots.txt</a></li>" +
		"</ul>" +
		"<ul>" +
		"<li><a href=\"/api/item/2\">Item de otro usuario (IDOR)</a></li>" +
		"<li><a href=\"/api/token\">JWT alg:none</a></li>" +
		"<li><a href=\"/fetch?url=http://127.0.0.1/\">Fetch (SSRF)</a></li>" +
		"<li><a href=\"/render?tpl={{7*7}}\">Render (SSTI)</a></li>" +
		"<li><a href=\"/redirect?u=https://evil.example/\">Redirect (open redirect)</a></li>" +
		"<li><a href=\"/download?file=../../../../etc/passwd\">Download (traversal)</a></li>" +
		"<li><a href=\"/ping?host=127.0.0.1\">Ping (command injection)</a></li>" +
		"<li><a href=\"/graphql\">GraphQL</a></li>" +
		"<li><a href=\"/debug/vars\">Debug vars</a></li>" +
		"</ul>"
	fmt.Fprint(w, page("Argos Practice Target", body))
}

// evalFakeSQL simulates a vulnerable SQL query for demonstration purposes:
//   - a bare quote produces a 500 with a "SQL syntax error" body (error marker)
//   - a tautology ("'1'='1") returns the same result set as the baseline
//   - a contradiction ("'1'='2") returns zero rows
func evalFakeSQL(q string) (rows int, sqlerr bool) {
	lq := strings.ToLower(q)
	switch {
	case strings.Contains(lq, "'1'='2") || strings.Contains(lq, "1'='0") ||
		strings.Contains(lq, " or '1'='2"):
		return 0, false
	case strings.Contains(lq, "'1'='1") || strings.Contains(lq, " or '1'='1"):
		return 1, false
	case strings.Contains(q, "'"):
		return 0, true
	case q == "":
		return 0, false
	default:
		return 1, false
	}
}

func queryResults(w http.ResponseWriter, r *http.Request, param, label, zeroMsg string) {
	q := r.URL.Query().Get(param)
	rows, sqlerr := evalFakeSQL(q)
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if sqlerr {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"SQL syntax error near '%s'"}`+"\n", q)
		return
	}
	if rows > 0 {
		fmt.Fprint(w, page("Resultados", "<h1>"+label+"</h1><p>1 resultado(s) encontrado(s)</p>"))
		return
	}
	fmt.Fprint(w, page("Resultados", "<h1>"+label+"</h1><p>"+zeroMsg+"</p>"))
}

func search(w http.ResponseWriter, r *http.Request) {
	queryResults(w, r, "q", "Búsqueda", "0 resultados para su búsqueda")
}

func item(w http.ResponseWriter, r *http.Request) {
	queryResults(w, r, "id", "Producto", "Producto no encontrado")
}

// profile reflects the user parameter unescaped (reflected XSS sink).
func profile(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if user == "" {
		user = "invitado"
	}
	fmt.Fprint(w, page("Perfil", "<h1>Perfil de "+user+"</h1><p>Bienvenido, "+user+"</p>"))
}

// login is a CSRF-less, rate-limit-less login form; the session cookie lacks
// Secure and HttpOnly flags.
func login(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodPost {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/"})
		fmt.Fprint(w, page("Login", "<h1>Sesión iniciada</h1><p>Bienvenido, "+r.FormValue("username")+"</p>"))
		return
	}
	body := "<h1>Iniciar sesión</h1><form method=\"POST\">" +
		"<input name=\"username\" placeholder=\"usuario\"><br>" +
		"<input name=\"password\" type=\"password\" placeholder=\"contraseña\"><br>" +
		"<button>Entrar</button></form>"
	fmt.Fprint(w, page("Login", body))
}

func admin(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page("Panel de administración", "<h1>Panel de administración</h1><p>Acceso sin autenticación.</p>"))
}

func apiHealth(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	// hidden "debug" parameter: changes the response shape (hidden param demo)
	if r.URL.Query().Get("debug") == "argos-probe" {
		fmt.Fprint(w, `{"status":"ok","probe":true,"debug":"argos-probe"}`+"\n")
		return
	}
	fmt.Fprint(w, `{"status":"ok"}`+"\n")
}

func apiVersion(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"name":"practice-target","version":"1.0.0","generator":"argos-practice-target"}`+"\n")
}

func robots(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\nDisallow: /api/\n")
}

func dotEnv(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "DB_PASSWORD=super-secret\nAPI_KEY=pk_test_fake\nFLAG=ARGOS{practice-target}\n")
}

func backupZip(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=backup.zip")
	// fake zip-ish bytes
	fmt.Fprint(w, "PK\x03\x04 fake backup archive with secrets")
}

// ---------------------------------------------------------------------------
// ARG-051: the vulnerability classes the benchmark had no coverage for.
// ---------------------------------------------------------------------------

// apiItem is a broken object level authorization (IDOR/BOLA): the handler
// returns the record of whoever the id points at without ever checking the
// session of the caller.
func apiItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/item/")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	n, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	// The owner of the record is never compared with the caller: any id
	// returns the record of its owner.
	fmt.Fprintf(w, `{"id":%d,"owner":"user-%d","email":"user-%d@example.com","balance":%d}`+"\n",
		n, n, n, 1000+n)
}

// apiToken issues a JWT signed with "alg": "none" and without exp, aud or
// iss: the token is accepted without any signature verification and never
// expires.
func apiToken(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","name":"admin","role":"admin"}`))
	token := header + "." + claims + "."
	// The token also travels in a response header so a scanner can read it
	// without parsing the body.
	w.Header().Set("Authorization", "Bearer "+token)
	fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer"}`+"\n", token)
}

// apiTransfer is a state changing endpoint without an anti-CSRF token and
// without any Origin validation: a third party page can make the browser of
// a logged in user call it.
func apiTransfer(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	amount := r.FormValue("amount")
	if amount == "" {
		amount = "0"
	}
	fmt.Fprintf(w, `{"status":"transferred","amount":%q}`+"\n", amount)
}

// apiCORS answers with a permissive CORS policy: every origin is accepted
// and the credentials are allowed too.
func apiCORS(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`+"\n")
}

// knownUsers are the accounts of the practice target.
var knownUsers = map[string]bool{"admin": true, "demo-user": true}

// apiLogin is a login endpoint without rate limiting whose response time
// tells the attacker whether the account exists: the password of a known
// account is hashed (slow) while an unknown one is rejected right away.
func apiLogin(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	user := r.URL.Query().Get("user")
	if user == "" {
		_ = r.ParseForm()
		user = r.FormValue("user")
	}
	if knownUsers[user] {
		// The hash of the password of an existing account.
		time.Sleep(250 * time.Millisecond)
	}
	// No throttle at all: every attempt is served.
	fmt.Fprintf(w, `{"status":"denied","user_exists":%t}`+"\n", knownUsers[user])
}

// couponUsed is the state of the single use coupon.
var couponUsed atomic.Bool

// apiCoupon redeems a single use coupon with a check-then-act sequence that
// is not atomic: two concurrent requests both pass the check and both redeem
// it.
func apiCoupon(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if couponUsed.Load() {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"status":"already-used"}`+"\n")
		return
	}
	// The window between the check and the write.
	time.Sleep(50 * time.Millisecond)
	couponUsed.Store(true)
	fmt.Fprint(w, `{"status":"redeemed"}`+"\n")
}

// apiDeserialize models the classic "deserialize an untrusted object" sink:
// the payload names the class to instantiate and the handler calls its run
// method, so the command of the payload reaches the shell.
func apiDeserialize(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	payload := strings.TrimSpace(string(raw))
	if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil && len(decoded) > 0 {
		payload = string(decoded)
	}
	command, ok := deserializeGadget(payload)
	if !ok {
		http.Error(w, "cannot unserialize", http.StatusBadRequest)
		return
	}
	out, err := runShellEcho(command)
	if err != nil {
		fmt.Fprintf(w, `{"status":"error","error":%q}`+"\n", err.Error())
		return
	}
	fmt.Fprintf(w, `{"status":"ok","output":%q}`+"\n", out)
}

// deserializeGadget reads the "cmd" property of a PHP-like serialized object.
func deserializeGadget(payload string) (string, bool) {
	marker := `s:3:"cmd"`
	index := strings.Index(payload, marker)
	if index < 0 {
		return "", false
	}
	rest := payload[index+len(marker):]
	match := regexp.MustCompile(`s:\d+:"([^"]*)"`).FindStringSubmatch(rest)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// apiData answers every HTTP verb, including the state changing ones it
// should reject: the endpoint is a verb tampering target.
func apiData(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		fmt.Fprintf(w, `{"status":"ok","method":%q}`+"\n", r.Method)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiCache serves a cacheable response whose body depends on the request
// headers without declaring them in Vary: a shared cache can serve the
// response of one tenant to another one.
func apiCache(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Cache-Control", "public, max-age=600")
	// No Vary header: the cached object is shared between every tenant.
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"host":%q,"user":%q}`+"\n",
		r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-User"))
}

// practiceFiles is the little filesystem the traversal and the XXE sinks read.
var practiceFiles = map[string]string{
	"/srv/app/public/readme.txt": "Argos practice target\n",
	"/srv/app/private/flag.txt":  "FLAG=ARGOS{practice-target-private}\n",
	"/etc/passwd":                "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
	"/etc/shadow":                "root:*:19000:0:99999:7:::\n",
}

// apiXML parses an XML document with an external entity resolver enabled: a
// DOCTYPE with a SYSTEM entity makes the parser read the local file and
// inline its content.
func apiXML(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, expandExternalEntities(string(raw)))
}

// externalEntityPattern matches the DOCTYPE declaration of an external entity.
var externalEntityPattern = regexp.MustCompile(`(?s)<!ENTITY\s+([A-Za-z0-9_.-]+)\s+SYSTEM\s+"([^"]+)"\s*>`)

// expandExternalEntities resolves the external entities of an XML document.
func expandExternalEntities(document string) string {
	for _, match := range externalEntityPattern.FindAllStringSubmatch(document, -1) {
		name, reference := match[1], match[2]
		content, ok := practiceFiles[strings.TrimPrefix(reference, "file://")]
		if !ok {
			content = "ENTITY NOT FOUND"
		}
		document = strings.ReplaceAll(document, "&"+name+";", content)
	}
	return document
}

// openAPI publishes the contract of the API: the endpoints, their parameters
// and their expected status codes.
func openAPI(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{
  "openapi": "3.0.0",
  "info": {"title": "Argos Practice Target API", "version": "1.0.0"},
  "paths": {
    "/api/item/{id}": {
      "get": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "responses": {"200": {"description": "the record of the owner of the id"}}
      }
    },
    "/api/transfer": {
      "post": {
        "responses": {"200": {"description": "the transfer was accepted"}}
      }
    },
    "/api/login": {
      "post": {
        "responses": {"200": {"description": "the credentials were rejected"}}
      }
    }
  }
}`+"\n")
}

// fetch is the server side request forgery sink: it fetches the URL it
// receives and returns its body (or the error of the failed fetch).
func fetch(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/plain")
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		// The error of the fetch names the internal address: the classic
		// blind SSRF leak.
		fmt.Fprintf(w, "fetch failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Fprintf(w, "fetched %d bytes from %s\n%s", len(body), target, body)
}

// templatePattern matches the template expressions the SSTI probes inject.
var templatePattern = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}|\$\{\s*([^{}]+?)\s*\}|<%=\s*([^{}]+?)\s*%>|#\{\s*([^{}]+?)\s*\}`)

// render evaluates the template it receives: the arithmetic expressions of
// the payload are computed by the server.
func render(w http.ResponseWriter, r *http.Request) {
	tpl := r.URL.Query().Get("tpl")
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page("Render", "<h1>Resultado</h1><p>"+evaluateTemplate(tpl)+"</p>"))
}

// evaluateTemplate replaces every template expression of the document with
// the value of the expression it evaluates to.
func evaluateTemplate(document string) string {
	return templatePattern.ReplaceAllStringFunc(document, func(match string) string {
		groups := templatePattern.FindStringSubmatch(match)
		for _, group := range groups[1:] {
			if group == "" {
				continue
			}
			if value, ok := evaluateArithmetic(group); ok {
				return value
			}
		}
		return match
	})
}

// evaluateArithmetic computes the "<number>*<number|quoted string>"
// expressions the template engines evaluate.
func evaluateArithmetic(expression string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(expression), "*", 2)
	if len(parts) != 2 {
		return "", false
	}
	left, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", false
	}
	right := strings.TrimSpace(parts[1])
	if len(right) >= 2 && (right[0] == '\'' || right[0] == '"') && right[len(right)-1] == right[0] {
		// A string operand is repeated: 7*'7' is "777777777".
		return strings.Repeat(right[1:len(right)-1], left), true
	}
	number, err := strconv.Atoi(right)
	if err != nil {
		return "", false
	}
	return strconv.Itoa(left * number), true
}

// redirect sends the caller to any destination: the destination is not
// validated against the allow list of the application.
func redirect(w http.ResponseWriter, r *http.Request) {
	destination := r.URL.Query().Get("u")
	if destination == "" {
		destination = "/"
	}
	commonHeaders(w)
	w.Header().Set("Location", destination)
	w.WriteHeader(http.StatusFound)
	fmt.Fprint(w, "redirecting\n")
}

// download serves a file of the local filesystem: the name it receives is
// joined with the base directory but the result is never checked, so the
// traversal escapes it.
func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		name = "readme.txt"
	}
	resolved := path.Clean(path.Join("/srv/app/public", name))
	commonHeaders(w)
	content, ok := practiceFiles[resolved]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, content)
}

// ping runs a shell command with the host it receives: the parameter is
// concatenated into the command line of the shell.
func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	out, err := runShellEcho(host)
	if err != nil {
		fmt.Fprintf(w, "ping failed: %v\n", err)
		return
	}
	fmt.Fprintf(w, "PING %s\n%s", host, out)
}

// runShellEcho runs the input in a shell. The base command is a harmless
// echo: the point of the practice target is the injection, not the payload.
func runShellEcho(input string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo "+input)
	} else {
		cmd = exec.Command("/bin/sh", "-c", "echo "+input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// graphql answers the GraphQL queries of the target: the introspection is
// open, the schema exposes sensitive fields, the mutations are unprotected,
// there is no depth limit and the endpoint accepts batched operations.
func graphql(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	body := strings.TrimSpace(string(raw))
	if strings.HasPrefix(body, "[") {
		// A batch of operations: every one of them is answered.
		var operations []json.RawMessage
		if err := json.Unmarshal([]byte(body), &operations); err == nil {
			answers := make([]any, 0, len(operations))
			for range operations {
				answers = append(answers, map[string]any{"data": map[string]any{"user": map[string]any{"id": "user-1"}}})
			}
			writeJSON(w, answers)
			return
		}
	}
	if strings.Contains(body, "__schema") {
		writeJSON(w, map[string]any{"data": map[string]any{"__schema": graphqlSchema()}})
		return
	}
	// Any other query is answered: there is no depth limit and no cost
	// limit either.
	writeJSON(w, map[string]any{"data": map[string]any{"user": map[string]any{"id": "user-1"}}})
}

func writeJSON(w http.ResponseWriter, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "cannot encode", http.StatusInternalServerError)
		return
	}
	w.Write(encoded)
}

// graphqlSchema is the schema the introspection hands out.
func graphqlSchema() map[string]any {
	field := func(name, typeName, kind string) map[string]any {
		return map[string]any{
			"name": name,
			"type": map[string]any{"name": typeName, "kind": kind, "ofType": map[string]any{"name": "", "kind": ""}},
		}
	}
	object := func(name string, fields ...map[string]any) map[string]any {
		return map[string]any{"name": name, "kind": "OBJECT", "fields": fields}
	}
	types := []any{
		object("Query",
			field("user", "User", "OBJECT"),
			field("orders", "OrderList", "OBJECT"),
		),
		object("User",
			field("id", "String", "SCALAR"),
			field("email", "String", "SCALAR"),
			field("password", "String", "SCALAR"),
			field("orders", "OrderList", "OBJECT"),
		),
		object("OrderList",
			field("total", "Int", "SCALAR"),
			field("items", "Order", "OBJECT"),
		),
		object("Order",
			field("id", "String", "SCALAR"),
			field("total", "Int", "SCALAR"),
		),
		object("Mutation",
			field("createUser", "User", "OBJECT"),
			field("deleteAccount", "Boolean", "SCALAR"),
		),
	}
	return map[string]any{
		"queryType":    map[string]any{"name": "Query"},
		"mutationType": map[string]any{"name": "Mutation"},
		"types":        types,
	}
}

// unicodePath models the inconsistent normalization of the path: the edge
// only removes the zero width characters before the block list check, so the
// fullwidth spelling of "admin" slips through and the backend resolves it.
func unicodePath(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/unicode/")
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if strings.Contains(strings.ToLower(stripZeroWidth(raw)), "admin") {
		http.Error(w, "blocked by the edge policy", http.StatusForbidden)
		return
	}
	if strings.Contains(foldWidth(raw), "admin") {
		fmt.Fprint(w, page("Admin", "<h1>Panel de administración</h1><p>Acceso sin autenticación.</p>"))
		return
	}
	http.NotFound(w, r)
}

// stripZeroWidth removes the zero width characters of a string.
func stripZeroWidth(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF':
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

// foldWidth maps the fullwidth spelling of the ASCII characters back to
// ASCII: the backend does it, the edge does not.
func foldWidth(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r >= 0xFF01 && r <= 0xFF5E {
			out.WriteRune(r - 0xFF01 + 0x21)
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

// debugVars exposes the configuration of the process, secrets included.
func debugVars(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"+
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"+
		"DB_PASSWORD=super-secret\n"+
		"APP_ENV=production\n"+
		"DEBUG=true\n")
}

// staticAppJS is the client bundle of the application: the API key of the
// backend travels in the JavaScript that every browser downloads.
func staticAppJS(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	fmt.Fprint(w, "const API_KEY = \"AKIAIOSFODNN7EXAMPLE\";\n"+
		"fetch(\"/api/orders\", { headers: { \"X-Api-Key\": API_KEY } });\n")
}

// gitIndex is the listing of the exposed git directory: the deployment
// forgot to remove it and the web server serves its content.
func gitIndex(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page(".git", "<h1>Index of /.git</h1><ul><li><a href=\"/.git/HEAD\">HEAD</a></li><li><a href=\"/.git/config\">config</a></li></ul>"))
}

// gitHEAD is the HEAD file of an exposed git repository.
func gitHEAD(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "ref: refs/heads/main\n")
}

// gitConfig is the configuration of an exposed git repository: the remote
// carries a personal access token.
func gitConfig(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "[core]\n"+
		"\trepositoryformatversion = 0\n"+
		"[remote \"origin\"]\n"+
		"\turl = https://x-access-token:ghp_0123456789abcdefghijklmnopqrstuvwxyz@github.com/acme/payments.git\n"+
		"\tfetch = +refs/heads/*:refs/remotes/origin/*\n")
}

// danglingHost is the host of the dangling subdomain: its DNS record still
// points to a bucket that was deleted.
const danglingHost = "dev.payments.acme-corp.local"

// danglingBucket answers the virtual host of the dangling subdomain with the
// error of a bucket that does not exist anymore: whoever owns the domain can
// take the subdomain over.
func danglingBucket(w http.ResponseWriter, r *http.Request) {
	commonHeaders(w)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
		`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>`+
		`<BucketName>payments</BucketName><RequestId>argos-practice</RequestId></Error>`+"\n")
}

// ---------------------------------------------------------------------------
// The broken front-end: the HTTP request smuggling vector.
// ---------------------------------------------------------------------------

// FrontProxy is a deliberately broken reverse proxy that sits in front of the
// practice target.
//
// The front-end trusts the Content-Length while the back-end trusts the
// Transfer-Encoding: a request that carries both headers leaves the two
// parsers disagreeing, which is the precondition of a request smuggling
// desynchronization. The proxy never answers an ambiguous request: it waits
// for the rest of the body that never arrives.
type FrontProxy struct {
	listener net.Listener
	backend  string
	client   *http.Client
	closed   chan struct{}
	once     sync.Once
}

// NewFrontProxy starts the front proxy in front of the given backend URL.
func NewFrontProxy(backend string) (*FrontProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proxy := &FrontProxy{
		listener: listener,
		backend:  strings.TrimRight(backend, "/"),
		client:   &http.Client{Timeout: 10 * time.Second},
		closed:   make(chan struct{}),
	}
	go proxy.serve()
	return proxy, nil
}

// URL returns the base URL of the front proxy.
func (p *FrontProxy) URL() string {
	return "http://" + p.listener.Addr().String()
}

// Close stops the front proxy and releases the port.
func (p *FrontProxy) Close() error {
	var err error
	p.once.Do(func() {
		close(p.closed)
		err = p.listener.Close()
	})
	return err
}

func (p *FrontProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

// handle serves one connection of the front proxy.
func (p *FrontProxy) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(conn)

	head, err := readHead(reader)
	if err != nil {
		return
	}
	lines := strings.Split(head, "\r\n")
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return
	}
	method, target := fields[0], fields[1]

	contentLength := 0
	chunked := false
	headers := http.Header{}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		switch strings.ToLower(name) {
		case "content-length":
			contentLength, _ = strconv.Atoi(value)
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(value), "chunked") {
				chunked = true
			}
		case "host", "connection":
			continue
		default:
			headers.Set(name, value)
		}
	}

	if contentLength > 0 && chunked {
		// The two parsers disagree. The front-end waits for the rest of
		// the body and never answers: the request never completes and the
		// connection is left in an inconsistent state.
		_, _ = io.Copy(io.Discard, reader)
		return
	}

	body := readBody(reader, contentLength, chunked)
	request, err := http.NewRequest(method, p.backend+target, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header = headers
	response, err := p.client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()

	// The proxy headers are the fingerprint of the intermediary: they are
	// what tells the scanner that there is a front-end in the path.
	out := []byte("HTTP/1.1 " + strconv.Itoa(response.StatusCode) + " " + http.StatusText(response.StatusCode) + "\r\n")
	for name, values := range response.Header {
		for _, value := range values {
			out = append(out, []byte(name+": "+value+"\r\n")...)
		}
	}
	out = append(out, []byte("Via: 1.1 argos-practice-front\r\n")...)
	out = append(out, []byte("X-Forwarded-For: 127.0.0.1\r\n")...)
	out = append(out, []byte("Connection: close\r\n\r\n")...)
	_, _ = conn.Write(out)
	_, _ = io.Copy(conn, response.Body)
}

// readHead reads the head of a request up to the empty line.
func readHead(reader *bufio.Reader) (string, error) {
	var head strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		head.WriteString(line)
		if line == "\r\n" || line == "\n" {
			return head.String(), nil
		}
	}
}

// readBody reads the body of a request with the framing the front-end
// trusts.
func readBody(reader *bufio.Reader, contentLength int, chunked bool) []byte {
	if chunked {
		var body bytes.Buffer
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			size, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
			if err != nil || size == 0 {
				break
			}
			chunk := make([]byte, size)
			if _, err := io.ReadFull(reader, chunk); err != nil {
				break
			}
			body.Write(chunk)
			_, _ = reader.ReadString('\n')
		}
		return body.Bytes()
	}
	if contentLength <= 0 {
		return nil
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return body
	}
	return body
}
