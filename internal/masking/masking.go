package masking

import (
	http1parser "nginxray/internal/parser"
)

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

func MaskRequest(req *http1parser.HTTPRequest) {
	maskHeaders(req.Headers)
	maskBody(req.Body)
}

func MaskResponse(req *http1parser.HTTPResponse) {
	maskHeaders(req.Headers)
	maskBody(req.Body)
}

func maskHeaders(headers map[string]string) {
	for headername := range headers {
		if _, exists := sensitiveHeaders[headername]; exists {
			headers[headername] = "***"
		}
	}
}

func maskBody(body []byte) {
}
