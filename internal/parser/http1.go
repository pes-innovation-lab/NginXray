package http1parser

import (
	"bytes"
	"fmt"
	"strings"
)

// structs to contain res/req
type HTTPRequest struct {
	Method  string
	Path    string
	Version string
	Headers map[string]string
	Body    []byte
}

type HTTPResponse struct {
	Version string
	Status  string
	Code    int
	Headers map[string]string
	Body    []byte
}

func ParseRequest(buf *bytes.Buffer) (*HTTPRequest, bool) {
	data := buf.Bytes()

	// header end signified by CRLF
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, false
	}

	headerBytes := data[:headerEnd]
	lines := bytes.Split(headerBytes, []byte("\r\n"))
	if len(lines) == 0 {
		return nil, false
	}

	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) != 3 {
		return nil, false
	}

	// obtain request line info
	req := &HTTPRequest{
		Method:  string(parts[0]),
		Path:    string(parts[1]),
		Version: string(parts[2]),
		Headers: make(map[string]string),
	}

	contentLength := -1
	chunked := false

	// map headers and check for chunking or content length
	for _, line := range lines[1:] {
		idx := bytes.IndexByte(line, ':')
		if idx == -1 {
			continue
		}

		key := strings.ToLower(string(bytes.TrimSpace(line[:idx])))
		val := string(bytes.TrimSpace(line[idx+1:]))

		req.Headers[key] = val

		switch key {
		case "content-length":
			fmt.Sscanf(val, "%d", &contentLength)

		case "transfer-encoding":
			chunked = strings.Contains(strings.ToLower(val), "chunked")
		}
	}

	// append body directly if not chunked
	if !chunked {
		if contentLength < 0 {
			contentLength = 0
		}

		total := headerEnd + 4 + contentLength
		if len(data) < total {
			return nil, false
		}

		req.Body = append([]byte(nil), data[headerEnd+4:total]...)
		buf.Next(total)
		return req, true
	}

	pos := headerEnd + 4
	var body []byte

	// handle chunking
	for {
		if pos >= len(data) {
			return nil, false
		}

		lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
		if lineEnd == -1 {
			return nil, false
		}

		sizeLine := string(data[pos : pos+lineEnd])
		sizeLine = strings.SplitN(sizeLine, ";", 2)[0]

		// obtain chunk size which is in hex
		var chunkSize int
		if _, err := fmt.Sscanf(sizeLine, "%x", &chunkSize); err != nil {
			return nil, false
		}

		pos += lineEnd + 2

		// break if end of chunking
		if chunkSize == 0 {
			break
		}

		if len(data) < pos+chunkSize+2 {
			return nil, false
		}

		body = append(body, data[pos:pos+chunkSize]...)

		pos += chunkSize

		if len(data) < pos+2 {
			return nil, false
		}

		pos += 2
	}

	// handle trailing headers
	for {
		if pos >= len(data) {
			return nil, false
		}

		lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
		if lineEnd == -1 {
			return nil, false
		}

		if lineEnd == 0 {
			pos += 2
			break
		}

		pos += lineEnd + 2
	}

	// move buffer pointer forward by pos since 1 request is consumed
	req.Body = body
	buf.Next(pos)

	return req, true
}

func ParseResponse(buf *bytes.Buffer) (*HTTPResponse, bool) {
	data := buf.Bytes()

	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, false
	}

	headerBytes := data[:headerEnd]
	lines := bytes.Split(headerBytes, []byte("\r\n"))
	if len(lines) == 0 {
		return nil, false
	}

	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 2 {
		return nil, false
	}

	resp := &HTTPResponse{
		Version: string(parts[0]),
		Headers: make(map[string]string),
	}

	if len(parts) == 3 {
		resp.Status = string(parts[2])
	}

	fmt.Sscanf(string(parts[1]), "%d", &resp.Code)

	// no body for these types of responses
	if (resp.Code >= 100 && resp.Code < 200) || resp.Code == 204 || resp.Code == 304 {
		buf.Next(headerEnd + 4)
		return resp, true
	}

	contentLength := -1
	chunked := false

	for _, line := range lines[1:] {
		idx := bytes.IndexByte(line, ':')
		if idx == -1 {
			continue
		}

		key := strings.ToLower(string(bytes.TrimSpace(line[:idx])))
		val := string(bytes.TrimSpace(line[idx+1:]))

		resp.Headers[key] = val

		switch key {
		case "content-length":
			fmt.Sscanf(val, "%d", &contentLength)

		case "transfer-encoding":
			chunked = strings.Contains(strings.ToLower(val), "chunked")
		}
	}

	if !chunked && contentLength >= 0 {
		total := headerEnd + 4 + contentLength

		if len(data) < total {
			return nil, false
		}

		resp.Body = append([]byte(nil), data[headerEnd+4:total]...)
		buf.Next(total)
		return resp, true
	}

	if chunked {
		pos := headerEnd + 4
		var body []byte

		for {
			if pos >= len(data) {
				return nil, false
			}

			lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
			if lineEnd == -1 {
				return nil, false
			}

			sizeLine := string(data[pos : pos+lineEnd])
			sizeLine = strings.SplitN(sizeLine, ";", 2)[0]

			var chunkSize int
			if _, err := fmt.Sscanf(sizeLine, "%x", &chunkSize); err != nil {
				return nil, false
			}

			pos += lineEnd + 2

			if chunkSize == 0 {
				break
			}

			if len(data) < pos+chunkSize+2 {
				return nil, false
			}

			body = append(body, data[pos:pos+chunkSize]...)

			pos += chunkSize

			if len(data) < pos+2 {
				return nil, false
			}

			pos += 2
		}

		for {
			if pos >= len(data) {
				return nil, false
			}

			lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
			if lineEnd == -1 {
				return nil, false
			}

			if lineEnd == 0 {
				pos += 2
				break
			}

			pos += lineEnd + 2
		}

		resp.Body = body
		buf.Next(pos)
		return resp, true
	}

	// handling different types of connections
	connectionHeader := strings.ToLower(resp.Headers["connection"])
	isPersistent := false
	switch resp.Version {
	case "HTTP/1.1":
		isPersistent = connectionHeader != "close"
	case "HTTP/1.0":
		isPersistent = connectionHeader == "keep-alive"
	}

	if isPersistent {
		buf.Next(headerEnd + 4)
		return resp, true
	}

	resp.Body = append([]byte(nil), data[headerEnd+4:]...)
	buf.Reset()

	return resp, true
}
