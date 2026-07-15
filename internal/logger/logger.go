package logging

import (
	"context"
	"log"
	"time"

	http1parser "nginxray/internal/parser"
)

type HTTPEvent struct {
	Timestamp string `json:"timestamp"`

	PID uint32 `json:"pid"`
	TID uint32 `json:"tid"`

	Direction string `json:"direction"`

	ClientIP   string `json:"clientIP"`
	ClientPort uint16 `json:"clientPort"`

	ServerIP   string `json:"serverIP"`
	ServerPort uint16 `json:"serverPort"`

	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`

	Version string `json:"version"`

	Status int `json:"status,omitempty"`

	Headers map[string]string `json:"headers"`

	Body string `json:"body"`
}

var eventQueue = make(chan HTTPEvent, 4096)

func startWorker() {
	go func() {
		for ev := range eventQueue {
			if err := indexEvent(ev); err != nil {
				log.Printf("logging to elasticsearch: %s", err)
			}
		}
	}()
}

func indexEvent(event HTTPEvent) error {
	if Client == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Client.Index("nginxray-http").
		Document(event).
		Do(ctx)

	return err
}

func enqueue(event HTTPEvent) {
	if Client == nil {
		return // logging disabled, drop silently
	}
	select {
	case eventQueue <- event:
	default:
		log.Printf("warning: elasticsearch queue full, dropping %s event", event.Direction)
	}
}

func LogRequest(req *http1parser.HTTPRequest, pid, tid uint32, clientIP string, clientPort uint16, serverIP string, serverPort uint16, t string) {
	enqueue(HTTPEvent{
		Timestamp: t,

		PID: pid,
		TID: tid,

		ClientIP:   clientIP,
		ClientPort: clientPort,
		ServerIP:   serverIP,
		ServerPort: serverPort,

		Direction: "request",

		Method:  req.Method,
		Path:    req.Path,
		Version: req.Version,

		Headers: req.Headers,
		Body:    string(req.Body),
	})
}

func LogResponse(resp *http1parser.HTTPResponse, pid, tid uint32, clientIP string, clientPort uint16, serverIP string, serverPort uint16, t string) {
	enqueue(HTTPEvent{
		Timestamp: t,

		PID: pid,
		TID: tid,

		ClientIP:   clientIP,
		ClientPort: clientPort,
		ServerIP:   serverIP,
		ServerPort: serverPort,

		Direction: "response",

		Version: resp.Version,
		Status:  resp.Code,

		Headers: resp.Headers,
		Body:    string(resp.Body),
	})
}
