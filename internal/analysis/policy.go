package analysis

type ClientState struct {
	Score int
}

var clients = make(map[string]*ClientState)

type Action int

const (
	Log Action = iota
	Block
)

func Decide(clientIP string, detections []Detection) Action {
	// nothing detected
	if len(detections) == 0 {
		return Log
	}

	// create state if first time seeing this client
	state, ok := clients[clientIP]
	if !ok {
		state = &ClientState{}
		clients[clientIP] = state
	}

	// add this request's score
	for _, det := range detections {
		state.Score += det.Score
	}

	// decide action
	if state.Score >= 70 {
		return Block
	}

	return Log
}
