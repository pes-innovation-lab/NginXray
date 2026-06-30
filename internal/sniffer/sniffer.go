package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/ssl_hook.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net/http"

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

type connection struct {
	request_buffer  bytes.Buffer
	response_buffer bytes.Buffer
}

func TryParseRequest(buf *bytes.Buffer) (*http.Request, bool, error) {
	b := buf.Bytes()

	// check for header end
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, false, nil
	}

	// parse the request
	reader := bufio.NewReader(bytes.NewReader(b))
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, false, nil
		}
		return nil, false, err
	}

	// read body
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err == io.ErrUnexpectedEOF {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	// replace body ReadAll consumed it
	req.Body = io.NopCloser(bytes.NewReader(body))

	//  figure out how many bytes were consumed
	consumed := len(b) - reader.Buffered()

	// remove consumed bytes from the connection buffer
	buf.Next(consumed)

	return req, true, nil
}

func TryParseResponse(buf *bytes.Buffer) (*http.Response, bool, error) {
	b := buf.Bytes()

	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, false, nil
	}

	reader := bufio.NewReader(bytes.NewReader(b))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, false, nil
		}
		return nil, false, err
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == io.ErrUnexpectedEOF {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))

	consumed := len(b) - reader.Buffered()
	buf.Next(consumed)

	return resp, true, nil
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
		log.Printf("TIME:%d TID:%d PID:%d LEN:%d \n %s \n", buf.Timens, buf.Pid, buf.Tid, buf.Len, string(buf.Buf[:buf.Len]))

		conn := connections[buf.SSL_ptr]
		if conn == nil {
			conn = &connection{}
			connections[buf.SSL_ptr] = conn
		}
		if buf.Dir == 0 {
			conn.request_buffer.Write(buf.Buf[:buf.Len])

			for {
				req, ok, err := TryParseRequest(&conn.request_buffer)
				if err != nil {
					log.Println(err)
					break
				}
				if !ok {
					break
				}

				log.Printf("%s %s", req.Method, req.URL)
			}
		} else {
			conn.response_buffer.Write(buf.Buf[:buf.Len])

			for {
				resp, ok, err := TryParseResponse(&conn.response_buffer)
				if err != nil {
					log.Println(err)
					break
				}
				if !ok {
					break
				}

				log.Printf("%s", resp.Status)
			}
		}
	}
}
