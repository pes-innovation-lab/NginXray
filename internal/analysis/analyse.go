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

// maybe something we can look at later
// func AnalyseResp(res parser.HTTPResponse) []Detection {
//
// }
//

// this function calls all other checking functions
func AnalyseReq(req parser.HTTPRequest, ctx RequestContext) []Detection {
	var detections []Detection

	if det := detectSQLi(req, ctx); det != nil {
		detections = append(detections, *det)
	}

	return detections
}

// for detecting sql injections
func detectSQLi(req parser.HTTPRequest, ctx RequestContext) *Detection {
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
