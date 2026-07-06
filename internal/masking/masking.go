package masking

import (
	"encoding/json"
	"regexp"
	"strings"

	http1parser "nginxray/internal/parser"
)

// headers and feilds we mask
var sensitiveHeaders = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"x-api-key":            {},
	"x-auth-token":         {},
	"x-csrf-token":         {},
	"x-amz-security-token": {},
}

var sensitiveFields = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pwd":           {},
	"token":         {},
	"access_token":  {},
	"refresh_token": {},
	"secret":        {},
	"client_secret": {},
	"api_key":       {},
	"apikey":        {},
	"email":         {},
	"phone":         {},
	"ssn":           {},
	"credit_card":   {},
	"card_number":   {},
	"private_key":   {},
	"jwt":           {},
}

// regexes used for plaintext body masking
var plaintextPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*([^\s&,"']+)`),
		`$1=[REDACTED]`,
	},
	{
		regexp.MustCompile(`(?i)(token|access_token|refresh_token|jwt|api_key|apikey|client_secret|secret)\s*[:=]\s*([^\s&,"']+)`),
		`$1=[REDACTED]`,
	},
	{
		regexp.MustCompile(`(?i)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}`),
		`[REDACTED_EMAIL]`,
	},
	{
		regexp.MustCompile(`\b(?:\+?\d{1,3}[- ]?)?(?:\d{10}|\d{3}[- ]\d{3}[- ]\d{4})\b`),
		`[REDACTED_PHONE]`,
	},
	{
		regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
		`[REDACTED_CARD]`,
	},
}

func MaskRequest(req *http1parser.HTTPRequest) {
	maskHeaders(req.Headers)
	req.Body = maskBody(req.Body)
}

func MaskResponse(resp *http1parser.HTTPResponse) {
	maskHeaders(resp.Headers)
	resp.Body = maskBody(resp.Body)
}

func maskHeaders(headers map[string]string) {
	for headerName := range headers {
		if _, exists := sensitiveHeaders[strings.ToLower(headerName)]; exists {
			headers[headerName] = "[REDEACTED]"
		}
	}
}

// first tries to mask JSON, otherwise falls back to plaintext masking
func maskBody(body []byte) []byte {
	var obj any

	// JSON body
	if err := json.Unmarshal(body, &obj); err == nil {
		maskJSON(obj)

		masked, err := json.Marshal(obj)
		if err != nil {
			return body
		}

		return masked
	}

	// plaintext body
	return maskPlaintext(body)
}

// recursively mask all sensitive json feilds
func maskJSON(v any) {
	switch x := v.(type) {

	case map[string]any:
		for key, value := range x {

			if _, ok := sensitiveFields[strings.ToLower(key)]; ok {
				x[key] = "[REDACTED]"
				continue
			}

			maskJSON(value)
		}

	case []any:
		for _, item := range x {
			maskJSON(item)
		}
	}
}

// masks common sensitive information in plaintext bodies
func maskPlaintext(body []byte) []byte {
	s := string(body)

	for _, p := range plaintextPatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}

	return []byte(s)
}

