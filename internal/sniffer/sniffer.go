package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/ssl_hook.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	http1parser "nginxray/internal/parser"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)


type connection struct {
	request_buffer  bytes.Buffer
	response_buffer bytes.Buffer
	proto           int // http1parser.ProtoUnknown / ProtoHTTP1 / ProtoHTTP2
	h2              *http1parser.HTTP2Conn
	h2logged        bool // whether we've already logged this connection's poison
}

// struct for sslbuffer
type sslbuffer struct {
	Timens  uint64
	Tid     uint32
	Pid     uint32
	Len     uint32
	Dir     uint32
	SSL_ptr uint64
	Buf     [8192]byte
}


const maxCapturedRead = 8191

func printH2Request(pid, tid uint32, m http1parser.CompletedRequest) {
	fmt.Printf("pid=%d tid=%d [h2 stream %d]\n%s %s %s\n",
		pid, tid, m.StreamID, m.Request.Method, m.Request.Path, m.Request.Version)
	for k, v := range m.Request.Headers {
		fmt.Printf("%s: %s\n", k, v)
	}
	fmt.Printf("\n%s\n", m.Request.Body)
	if m.BodyTruncated {
		fmt.Print("[body truncated]\n")
	}
	fmt.Print("\n")
}

func printH2Response(pid, tid uint32, m http1parser.CompletedResponse) {
	fmt.Printf("pid=%d tid=%d [h2 stream %d]\n%s %d %s\n",
		pid, tid, m.StreamID, m.Response.Version, m.Response.Code, m.Response.Status)
	for k, v := range m.Response.Headers {
		fmt.Printf("%s: %s\n", k, v)
	}
	fmt.Printf("\n%s\n", m.Response.Body)
	if m.BodyTruncated {
		fmt.Print("[body truncated]\n")
	}
	fmt.Print("\n")
}

// logPoison reports an h2 poison once per connection, so a desynced connection
func logPoison(conn *connection) {
	if conn.h2 != nil && conn.h2.Poisoned() && !conn.h2logged {
		conn.h2logged = true
		log.Printf("http2: connection poisoned (%s)", conn.h2.PoisonReason())
	}
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

	connections := make(map[uint64]*connection)

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

		conn := connections[buf.SSL_ptr]
		if conn == nil {
			conn = &connection{}
			connections[buf.SSL_ptr] = conn
		}


		isReq := buf.Dir == 1
		data := buf.Buf[:buf.Len]

		
		if conn.proto == http1parser.ProtoHTTP2 {
			truncated := buf.Len == maxCapturedRead
			if isReq {
				for _, m := range conn.h2.FeedRequest(data, truncated) {
					printH2Request(buf.Pid, buf.Tid, m)
				}
			} else {
				for _, m := range conn.h2.FeedResponse(data, truncated) {
					printH2Response(buf.Pid, buf.Tid, m)
				}
			}
			logPoison(conn)
			continue
		}

		
		if isReq {
			conn.request_buffer.Write(data)
		} else {
			conn.response_buffer.Write(data)
		}

		if conn.proto == http1parser.ProtoUnknown {
			switch http1parser.DetectProto(conn.request_buffer.Bytes()) {
			case http1parser.ProtoHTTP2:
				conn.proto = http1parser.ProtoHTTP2
				conn.h2 = http1parser.NewHTTP2Conn()
				rb := conn.request_buffer.Bytes()
				for _, m := range conn.h2.FeedRequest(rb[http1parser.PrefaceLen:], false) {
					printH2Request(buf.Pid, buf.Tid, m)
				}
				conn.request_buffer.Reset()
				if conn.response_buffer.Len() > 0 { // drain any early response bytes
					for _, m := range conn.h2.FeedResponse(conn.response_buffer.Bytes(), false) {
						printH2Response(buf.Pid, buf.Tid, m)
					}
					conn.response_buffer.Reset()
				}
				logPoison(conn)
				continue
			case http1parser.ProtoHTTP1:
				conn.proto = http1parser.ProtoHTTP1
				// fall through to the HTTP/1.1 path below
			default:
				continue // not enough bytes yet to decide
			}
		}

		// HTTP/1.1 path 
		if isReq {
			for {
				req, ok := http1parser.ParseRequest(&conn.request_buffer)
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
			for {
				resp, ok := http1parser.ParseResponse(&conn.response_buffer)
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
