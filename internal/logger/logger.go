package logging

import (
	"context"
	"time"

	http1parser "nginxray/internal/parser"
)

type HTTPEvent struct {
	Timestamp string `json:"timestamp"`

	PID uint32 `json:"pid"`
	TID uint32 `json:"tid"`

	Direction string `json:"direction"`

	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`

	Version string `json:"version"`

	Status int `json:"status,omitempty"`

	Headers map[string]string `json:"headers"`

	Body string `json:"body"`
}

// index http event as elasticsearch document
func Log(event HTTPEvent) error {
	_, err := Client.Index("nginxray-http").
		Document(event).
		Do(context.Background())

	return err
}

// convert resp and req to http event
func LogRequest(req *http1parser.HTTPRequest, pid, tid uint32) error {
	event := HTTPEvent{
		Timestamp: time.Now().Format(time.RFC3339),

		PID: pid,
		TID: tid,

		Direction: "request",

		Method:  req.Method,
		Path:    req.Path,
		Version: req.Version,

		Headers: req.Headers,
		Body:    string(req.Body),
	}

	return Log(event)
}

func LogResponse(resp *http1parser.HTTPResponse, pid, tid uint32) error {
	event := HTTPEvent{
		Timestamp: time.Now().Format(time.RFC3339),

		PID: pid,
		TID: tid,

		Direction: "response",

		Version: resp.Version,
		Status:  resp.Code,

		Headers: resp.Headers,
		Body:    string(resp.Body),
	}

	return Log(event)
}
