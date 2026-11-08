package guard

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Signature is a WAF fingerprint: a set of response headers and body
// markers that identify a vendor without sending a single probe payload.
type Signature struct {
	Name    string
	Headers [][2]string // [header name, substring]
	Body    []string    // body substrings
}

// wafSignatures are the fingerprints the breaker consults.
var wafSignatures = []Signature{
	{Name: "Cloudflare", Headers: [][2]string{{"cf-ray", ""}, {"server", "cloudflare"}, {"set-cookie", "__cf_bm"}}},
	{Name: "AWS WAF", Headers: [][2]string{{"x-amzn-requestid", ""}, {"x-amzn-cf-id", ""}}, Body: []string{"Request blocked", "AWS WAF"}},
	{Name: "Sucuri / CloudProxy", Headers: [][2]string{{"x-sucuri-id", ""}, {"server", "sucuri"}}},
	{Name: "Imperva / Incapsula", Headers: [][2]string{{"x-cdn", "incap"}, {"x-iinfo", ""}}, Body: []string{"incapsula"}},
	{Name: "Akamai Ghost", Headers: [][2]string{{"server", "akamaighost"}, {"x-akamai", ""}, {"server", "akamai"}}},
	{Name: "F5 BIG-IP ASM", Headers: [][2]string{{"set-cookie", "bigip"}}},
	{Name: "ModSecurity", Headers: [][2]string{{"server", "mod_security"}}, Body: []string{"ModSecurity"}},
	{Name: "Wordfence", Body: []string{"Wordfence"}},
	{Name: "Barracuda WAF", Headers: [][2]string{{"set-cookie", "barra_counter_session"}, {"server", "barracuda"}}},
	{Name: "Fastly", Headers: [][2]string{{"x-served-by", "fastly"}, {"x-fastly", ""}}},
	{Name: "StackPath", Headers: [][2]string{{"x-provided-by", "stackpath"}}},
	{Name: "Cisco ACE XML Gateway", Headers: [][2]string{{"x-via", "ace xml gateway"}}},
	{Name: "Citrix NetScaler", Headers: [][2]string{{"ns_af", ""}, {"citrix_ns_id", ""}}},
	{Name: "Radware", Headers: [][2]string{{"x-request-ip", ""}}},
}

// wafUserAgent is the browser-like agent used for the fingerprint request:
// WAFs answer differently to obvious scanners.
const wafUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

// DetectWAFDetailed returns every vendor that matched plus the evidence that
// produced the match (the header or body marker that identified it).
func DetectWAFDetailed(client *http.Client, target string) ([]string, map[string]string, error) {
	return DetectWAFDetailedContext(context.Background(), client, target)
}

func DetectWAFDetailedContext(ctx context.Context, client *http.Client, target string) ([]string, map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		return nil, nil, fmt.Errorf("waf detection requires a scope-bound client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("waf probe request: %w", err)
	}
	req.Header.Set("User-Agent", wafUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("waf probe request: %w", err)
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	one := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(one)
		body = append(body, one[:n]...)
		if err != nil || len(body) > 256<<10 {
			break
		}
	}
	vendors, evidence := FingerprintWAFResponse(resp.Header, body)
	return vendors, evidence, nil
}

func FingerprintWAFResponse(headers http.Header, body []byte) ([]string, map[string]string) {
	low := strings.ToLower(string(body))

	detected := make([]string, 0)
	evidence := map[string]string{}
	for _, sig := range wafSignatures {
		hit := false
		why := ""
		for _, hv := range sig.Headers {
			val := headers.Get(hv[0])
			if val == "" {
				continue
			}
			if hv[1] == "" || strings.Contains(strings.ToLower(val), hv[1]) {
				hit = true
				why = fmt.Sprintf("%s: %s", hv[0], truncate(val, 60))
				break
			}
		}
		if !hit {
			for _, b := range sig.Body {
				if strings.Contains(low, strings.ToLower(b)) {
					hit = true
					why = "body: " + b
					break
				}
			}
		}
		if hit {
			detected = append(detected, sig.Name)
			evidence[sig.Name] = why
		}
	}
	return detected, evidence
}

// truncate shortens a header value for the evidence map.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
