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
	"aadhaar":        {},
	"aadhaar_number": {},
	"pan":            {},
	"pan_number":     {},
	"upi":            {},
	"upi_id":         {},
	"ifsc":           {},
	"account_number": {},
	"bank_account":   {},
	"passport":       {},
	"passport_no":    {},
	"driver_license": {},
	"dl":             {},
	"voter_id":       {},
	"cvv":            {},
	"expiry":         {},
	"expiry_date":    {},
	"dob":            {},
	"date_of_birth":  {},
}

// regexes used for plaintext body masking
var plaintextPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// passwords
	{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*([^\s&,"']+)`),
		`$1=[REDACTED]`,
	},

	// tokens / secrets
	{
		regexp.MustCompile(`(?i)(token|access_token|refresh_token|jwt|api_key|apikey|client_secret|secret|bearer)\s*[:=]\s*([^\s&,"']+)`),
		`$1=[REDACTED]`,
	},

	// Authorization: Bearer ...
	{
		regexp.MustCompile(`(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9\-._~+/]+=*`),
		`Authorization: Bearer [REDACTED]`,
	},

	// JWT
	{
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+`),
		`[REDACTED_JWT]`,
	},

	// email
	{
		regexp.MustCompile(`(?i)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}`),
		`[REDACTED_EMAIL]`,
	},

	// phone numbers
	{
		regexp.MustCompile(`(?:\+91[- ]?)?[6-9]\d{9}`),
		`[REDACTED_PHONE]`,
	},

	// Aadhaar
	{
		regexp.MustCompile(`\b\d{4}\s?\d{4}\s?\d{4}\b`),
		`[REDACTED_AADHAAR]`,
	},

	// PAN
	{
		regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`),
		`[REDACTED_PAN]`,
	},

	// UPI ID
	{
		regexp.MustCompile(`\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b`),
		`[REDACTED_UPI]`,
	},

	// IFSC
	{
		regexp.MustCompile(`\b[A-Z]{4}0[A-Z0-9]{6}\b`),
		`[REDACTED_IFSC]`,
	},

	// Passport
	{
		regexp.MustCompile(`\b[A-Z][0-9]{7}\b`),
		`[REDACTED_PASSPORT]`,
	},
	// Voter ID
	{
		regexp.MustCompile(`\b[A-Z]{3}[0-9]{7}\b`),
		`[REDACTED_VOTER_ID]`,
	},

	// Credit/Debit card
	{
		regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
		`[REDACTED_CARD]`,
	},
	// IPv4
	{
		regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		`[REDACTED_IP]`,
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
			headers[headerName] = "[REDACTED_HEADER]"
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
