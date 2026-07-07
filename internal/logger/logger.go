package logging

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
