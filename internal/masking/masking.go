package masking

import (
	"encoding/json"
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

func MaskRequest(req *http1parser.HTTPRequest) {
	maskHeaders(req.Headers)
	req.Body = maskBody(req.Body)
}

func MaskResponse(req *http1parser.HTTPResponse) {
	maskHeaders(req.Headers)
	req.Body = maskBody(req.Body)
}

func maskHeaders(headers map[string]string) {
	for headername := range headers {
		if _, exists := sensitiveHeaders[headername]; exists {
			headers[headername] = "***"
		}
	}
}

// for now only masks json
func maskBody(body []byte) []byte {
	var obj any

	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}

	maskJSON(obj)

	masked, err := json.Marshal(obj)
	if err != nil {
		return body
	}

	return masked
}

// recursiveley mask all json feilds
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
