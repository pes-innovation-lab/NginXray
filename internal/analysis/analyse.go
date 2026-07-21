package analysis

import (
	"net/url"
	"strings"

	parser "nginxray/internal/parser"
)

// for attaching time and client ip to detection log
type RequestContext struct {
	Timestamp string
	ClientIP  string
}

// the struct sent to the log
type Detection struct {
	Timestamp string
	ClientIP  string

	Method string
	Path   string

	AttackType string
	Pattern    string

	Score int
}

// make the detector functions into a type for easier use
type Detector func(RequestContext, parser.HTTPRequest) *Detection

// list all detectors to loop through
var detectors = []Detector{
	detectSQLi,
	detectCmdi,
	detectTraversal,
}

// common sql patterns to check against
var sqlPatterns = []string{
	"union select",
	"or 1=1",
	"drop table",
	"information_schema",
	"sleep(",
	"benchmark(",
	"waitfor delay",
}

var cmdPatterns = []string{
	// Shell operators
	";",
	"&&",
	"||",
	"|",
	"`",
	"$(",

	// Common commands
	"bash",
	"sh",
	"cmd.exe",
	"powershell",
	"wget",
	"curl",
	"nc",
	"netcat",
	"python",
	"perl",

	// File/system commands
	"cat /etc/passwd",
	"cat /etc/shadow",
	"whoami",
	"uname -a",
	"ls",
	"pwd",

	// Dangerous commands
	"rm -rf",
	"chmod",
	"chown",
	"mkfifo",
}

var traversalPatterns = []string{
	"../",
	"..\\",
	"/etc/passwd",
	"/etc/shadow",
	"windows/system32",
	"boot.ini",
}

var xssPatterns = []string{
	"localstorage",
	"sessionstorage",
	"document.cookie",
	"xmlhttpRequest",
	"location",
}

// maybe something we can look at later
// func AnalyseResp(res parser.HTTPResponse) []Detection {
//
// }
//

// this function calls all other checking functions
func AnalyseReq(req parser.HTTPRequest, ctx RequestContext) []Detection {
	var detections []Detection

	for _, detector := range detectors {
		if det := detector(ctx, req); det != nil {
			detections = append(detections, *det)
			break
		}
	}
	return detections
}

// for detecting sql injections
func detectSQLi(ctx RequestContext, req parser.HTTPRequest) *Detection {
	// for better string operations
	var input strings.Builder

	input.WriteString(req.Path)
	input.WriteString(" ")

	input.Write(req.Body)

	data := strings.ToLower(input.String())

	// decode if needed
	if decoded, err := url.QueryUnescape(data); err == nil {
		data = decoded
	}

	// check against patterns
	for _, pattern := range sqlPatterns {
		if strings.Contains(data, pattern) {
			return &Detection{
				Timestamp:  ctx.Timestamp,
				ClientIP:   ctx.ClientIP,
				Method:     req.Method,
				Path:       req.Path,
				AttackType: "SQL Injection",
				Pattern:    pattern,
				// will think of a proper implementation for score later
				Score: 90,
			}
		}
	}

	return nil
}

func detectCmdi(ctx RequestContext, req parser.HTTPRequest) *Detection {
	var input strings.Builder

	input.WriteString(req.Path)
	input.WriteString(" ")

	input.Write(req.Body)

	data := strings.ToLower(input.String())

	if decoded, err := url.QueryUnescape(data); err == nil {
		data = decoded
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(data, pattern) {
			return &Detection{
				Timestamp:  ctx.Timestamp,
				ClientIP:   ctx.ClientIP,
				Method:     req.Method,
				Path:       req.Path,
				AttackType: "Command Injection",
				Pattern:    pattern,
				Score:      90,
			}
		}
	}
	return nil
}

func detectTraversal(ctx RequestContext, req parser.HTTPRequest) *Detection {
	var input strings.Builder

	input.WriteString(req.Path)

	data := strings.ToLower(input.String())

	if decoded, err := url.QueryUnescape(data); err == nil {
		data = decoded
	}

	for _, pattern := range traversalPatterns {
		if strings.Contains(data, pattern) {
			return &Detection{
				Timestamp:  ctx.Timestamp,
				ClientIP:   ctx.ClientIP,
				Method:     req.Method,
				Path:       req.Path,
				AttackType: "Path Traversal",
				Pattern:    pattern,
				Score:      90,
			}
		}
	}
	return nil
}

func detectXSS(ctx RequestContext, req parser.HTTPRequest) *Detection {
	var input strings.Builder

	input.WriteString(req.Path)
	input.WriteString(" ")

	input.Write(req.Body)

	data := strings.ToLower(input.String())

	if decoded, err := url.QueryUnescape(data); err == nil {
		data = decoded
	}

	for _, pattern := range xssPatterns {
		if strings.Contains(data, pattern) {
			return &Detection{
				Timestamp:  ctx.Timestamp,
				ClientIP:   ctx.ClientIP,
				Method:     req.Method,
				Path:       req.Path,
				AttackType: "XSS",
				Pattern:    pattern,
				Score:      90,
			}
		}
	}
	return nil
}
