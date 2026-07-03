package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/ssl_hook.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// struct for sslbuffer
type sslbuffer struct {
	Timens  uint64
	Tid     uint32
	Pid     uint32
	Len     uint32
	Dir     uint32
	SSL_ptr uint64
	Buf     [8160]byte
}

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

type connection struct {
	request_buffer  bytes.Buffer
	response_buffer bytes.Buffer
}

func ParseRequest(buf *bytes.Buffer) (*HTTPRequest, bool) {
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
	if len(parts) != 3 {
		return nil, false
	}

	req := &HTTPRequest{
		Method:  string(parts[0]),
		Path:    string(parts[1]),
		Version: string(parts[2]),
		Headers: make(map[string]string),
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

		req.Headers[key] = val

		switch key {
		case "content-length":
			fmt.Sscanf(val, "%d", &contentLength)

		case "transfer-encoding":
			chunked = strings.Contains(strings.ToLower(val), "chunked")
		}
	}

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

		if len(data) < pos+chunkSize+2 {
			return nil, false
		}

		body = append(body, data[pos:pos+chunkSize]...)

		pos += chunkSize

		if len(data) < pos+2 {
			return nil, false
		}

		pos += 2

		if chunkSize == 0 {
			break
		}
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
	if len(parts) < 3 {
		return nil, false
	}

	resp := &HTTPResponse{
		Version: string(parts[0]),
		Status:  string(parts[2]),
		Headers: make(map[string]string),
	}

	fmt.Sscanf(string(parts[1]), "%d", &resp.Code)

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

			if len(data) < pos+chunkSize+2 {
				return nil, false
			}

			body = append(body, data[pos:pos+chunkSize]...)

			pos += chunkSize

			if len(data) < pos+2 {
				return nil, false
			}

			pos += 2
			if chunkSize == 0 {
				break
			}
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

	resp.Body = append([]byte(nil), data[headerEnd+4:]...)
	buf.Reset()

	return resp, true
}

func main() {
	// only for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock %s", err)
	}

	// load objects
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading ebpf  eobjects %s", err)
	}
	defer objs.Close()

	// get ssl executable
	exec, err := link.OpenExecutable("/usr/lib/libssl.so.3")
	if err != nil {
		log.Fatalf("opening executable %s", err)
	}

	// get hooks onto the specified symbols
	readentry, err := exec.Uprobe("SSL_read", objs.SslReadEntry, nil)
	if err != nil {
		log.Fatalf("loading sslreadentry %s", err)
	}
	defer readentry.Close()

	readexit, err := exec.Uretprobe("SSL_read", objs.SslReadExit, nil)
	if err != nil {
		log.Fatalf("loading sslreadexit %s", err)
	}
	defer readexit.Close()

	writeentry, err := exec.Uprobe("SSL_write", objs.SslWriteEntry, nil)
	if err != nil {
		log.Fatalf("loading sslwriteentry %s", err)
	}
	defer writeentry.Close()

	writeexit, err := exec.Uretprobe("SSL_write", objs.SslWriteExit, nil)
	if err != nil {
		log.Fatalf("loading sslwriteexit %s", err)
	}
	defer writeexit.Close()

	// create reader for ringuffer
	rd, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		log.Fatalf("creating ringbuffer reader %s", err)
	}

	connections := map[uint64]*connection{}

	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("reading ringbuf %s", err)
			continue
		}

		var buf sslbuffer

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &buf)
		if err != nil {
			log.Printf("copying into ssl buffer %s", err)
			continue
		}
		// log.Printf("TIME:%d TID:%d PID:%d LEN:%d \n %s \n", buf.Timens, buf.Pid, buf.Tid, buf.Len, string(buf.Buf[:buf.Len]))
		//
		conn := connections[buf.SSL_ptr]
		if conn == nil {
			conn = &connection{}
			connections[buf.SSL_ptr] = conn
		}
		if buf.Dir == 0 {
			conn.request_buffer.Write(buf.Buf[:buf.Len])

			for {
				req, ok := ParseRequest(&conn.request_buffer)
				if !ok {
					break
				}

				fmt.Printf(
					"pid=%d tid=%d\n%s %s %s\n",
					buf.Pid,
					buf.Tid,
					req.Method,
					req.Path,
					req.Version,
				)

				for k, v := range req.Headers {
					fmt.Printf("%s: %s\n", k, v)
				}

				fmt.Printf("\n%s\n\n", req.Body)
			}
		} else {
			conn.response_buffer.Write(buf.Buf[:buf.Len])
			for {
				resp, ok := ParseResponse(&conn.response_buffer)
				if !ok {
					break
				}

				fmt.Printf(
					"pid=%d tid=%d\n%s %d %s\n",
					buf.Pid,
					buf.Tid,
					resp.Version,
					resp.Code,
					resp.Status,
				)

				for k, v := range resp.Headers {
					fmt.Printf("%s: %s\n", k, v)
				}

				fmt.Printf("\n%s\n\n", resp.Body)
			}
		}
	}
}

