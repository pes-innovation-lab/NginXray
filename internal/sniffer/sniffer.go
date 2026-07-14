package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/ssl_hook.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	logger "nginxray/internal/logger"
	masking "nginxray/internal/masking"
	http1parser "nginxray/internal/parser"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	dirSend  = 0
	dirRecv  = 1
	dirClose = 2

	afInet  = 2
	afInet6 = 10
)

type connection struct {
	request_buffer  bytes.Buffer
	response_buffer bytes.Buffer
	proto           int // http1parser.ProtoUnknown / ProtoHTTP1 / ProtoHTTP2
	h2              *http1parser.HTTP2Conn
	h2logged        bool // whether we've already logged this connection's poison
}

type sslbuffer struct {
	Timens      uint64
	Tid         uint32
	Pid         uint32
	Len         uint32
	Dir         uint32
	SSL_ptr     uint64
	Family      uint16
	Client_port uint16
	Server_port uint16
	Client_ip   [16]byte
	Server_ip   [16]byte
	Buf         [8192]byte
}

func ipStr(family uint16, raw [16]byte) string {
	if family == afInet6 {
		return net.IP(raw[:]).String()
	}
	return net.IP(raw[:4]).String()
}

const maxCapturedRead = 8191

func printH2Request(pid, tid uint32, clientIP string, clientPort uint16, serverIP string, serverPort uint16, m http1parser.CompletedRequest) {
	fmt.Printf("pid=%d tid=%d [h2 stream %d]\n%s %s %s\nclient=%s:%d server=%s:%d\n",
		pid, tid, m.StreamID, m.Request.Method, m.Request.Path, m.Request.Version,
		clientIP, clientPort, serverIP, serverPort)
	for k, v := range m.Request.Headers {
		fmt.Printf("%s: %s\n", k, v)
	}
	fmt.Printf("\n%s\n", m.Request.Body)
	if m.BodyTruncated {
		fmt.Print("[body truncated]\n")
	}
	fmt.Print("\n")
}

func printH2Response(pid, tid uint32, clientIP string, clientPort uint16, serverIP string, serverPort uint16, m http1parser.CompletedResponse) {
	fmt.Printf("pid=%d tid=%d [h2 stream %d]\n%s %d %s\nclient=%s:%d server=%s:%d\n",
		pid, tid, m.StreamID, m.Response.Version, m.Response.Code, m.Response.Status,
		clientIP, clientPort, serverIP, serverPort)
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

func findLibSSLPath() (string, error) {
	// common system paths to check first
	standardPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/libssl.so.3",
		"/usr/lib64/libssl.so.3",
		"/usr/lib/libssl.so.1.1",
	}

	for _, path := range standardPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// dynamic Fallback
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "libssl.so") {
				parts := strings.Split(line, "=> ")
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1]), nil
				}
			}
		}
	}

	return "", fmt.Errorf("libssl library path not found on this system")
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

	logger.Init()

	// get ssl executable
	path, err := findLibSSLPath()
	if err != nil {
		log.Fatalf("finding openssl path :%s", err)
	}
	libssl, err := link.OpenExecutable(path)
	if err != nil {
		log.Fatalf("opening executable %s", err)
	}

	// get hooks onto the specified symbols
	readentry, err := libssl.Uprobe("SSL_read", objs.SslReadEntry, nil)
	if err != nil {
		log.Fatalf("loading sslreadentry %s", err)
	}
	defer readentry.Close()

	readexit, err := libssl.Uretprobe("SSL_read", objs.SslReadExit, nil)
	if err != nil {
		log.Fatalf("loading sslreadexit %s", err)
	}
	defer readexit.Close()

	writeentry, err := libssl.Uprobe("SSL_write", objs.SslWriteEntry, nil)
	if err != nil {
		log.Fatalf("loading sslwriteentry %s", err)
	}
	defer writeentry.Close()

	writeexit, err := libssl.Uretprobe("SSL_write", objs.SslWriteExit, nil)
	if err != nil {
		log.Fatalf("loading sslwriteexit %s", err)
	}
	defer writeexit.Close()

	freeentry, err := libssl.Uprobe("SSL_free", objs.SslFreeEntry, nil)
	if err != nil {
		log.Fatalf("loading sslfreeentry %s", err)
	}
	defer freeentry.Close()

	inetAcceptExit, err := link.Kretprobe(
		"inet_csk_accept",
		objs.InetCskAcceptExit,
		nil,
	)
	if err != nil {
		log.Fatalf("attach inet_csk_accept: %v", err)
	}
	defer inetAcceptExit.Close()

	acceptExit, err := link.Kretprobe(
		"__x64_sys_accept",
		objs.AcceptExit,
		nil,
	)
	if err != nil {
		log.Fatalf("attach accept_exit: %v", err)
	}
	defer acceptExit.Close()

	accept4Exit, err := link.Kretprobe(
		"__x64_sys_accept4",
		objs.Accept4Exit,
		nil,
	)
	if err != nil {
		log.Fatalf("attach accept4_exit: %v", err)
	}
	defer accept4Exit.Close()
	setfd, err := libssl.Uprobe("SSL_set_fd", objs.SslSetFd, nil)
	if err != nil {
		log.Fatalf("loading ssl_set_fd: %v", err)
	}
	defer setfd.Close()

	// create reader for ringuffer
	rd, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		log.Fatalf("creating ringbuffer reader %s", err)
	}
	defer rd.Close()

	connections := make(map[uint64]*connection)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ringbuffer reader closed, exiting")
				return
			}
			log.Printf("reading ringbuf %s", err)
			continue
		}

		var buf sslbuffer

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &buf)
		if err != nil {
			log.Printf("copying into ssl buffer %s", err)
			continue
		}

		if buf.Dir == dirClose {
			delete(connections, buf.SSL_ptr)
			continue
		}

		// create a connnection if one does not exist
		conn := connections[buf.SSL_ptr]
		if conn == nil {
			conn = &connection{}
			connections[buf.SSL_ptr] = conn
		}
		isReq := buf.Dir == dirRecv
		data := buf.Buf[:buf.Len]

		clientIP := ipStr(buf.Family, buf.Client_ip)
		serverIP := ipStr(buf.Family, buf.Server_ip)

		if conn.proto == http1parser.ProtoHTTP2 {
			truncated := buf.Len == maxCapturedRead
			if isReq {
				for _, m := range conn.h2.FeedRequest(data, truncated) {
					masking.MaskRequest(m.Request)
					logger.LogRequest(m.Request, buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port)
					printH2Request(buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port, m)
				}
			} else {
				for _, m := range conn.h2.FeedResponse(data, truncated) {

					masking.MaskResponse(m.Response)
					logger.LogResponse(m.Response, buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port)
					printH2Response(buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port, m)
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
				if len(rb) >= http1parser.PrefaceLen {
					for _, m := range conn.h2.FeedRequest(rb[http1parser.PrefaceLen:], false) {
						masking.MaskRequest(m.Request)
						logger.LogRequest(m.Request, buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port)
						printH2Request(buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port, m)
					}
				}
				conn.request_buffer.Reset()
				if conn.response_buffer.Len() > 0 { // drain any early response bytes
					for _, m := range conn.h2.FeedResponse(conn.response_buffer.Bytes(), false) {
						masking.MaskResponse(m.Response)
						logger.LogResponse(m.Response, buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port)
						printH2Response(buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port, m)
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

				// mask req before printing
				masking.MaskRequest(req)
				// log to elasticsearch
				logger.LogRequest(req, buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port)

				fmt.Printf(
					"pid=%d tid=%d\n%s %s %s\nclient=%s:%d server=%s:%d\n",
					buf.Pid,
					buf.Tid,
					req.Method,
					req.Path,
					req.Version,
					clientIP,
					buf.Client_port,
					serverIP,
					buf.Server_port,
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

				masking.MaskResponse(resp)
				logger.LogResponse(resp, buf.Pid, buf.Tid, clientIP, buf.Client_port, serverIP, buf.Server_port)

				fmt.Printf(
					"pid=%d tid=%d\n%s %d %s\nclient=%s:%d server=%s:%d\n",
					buf.Pid,
					buf.Tid,
					resp.Version,
					resp.Code,
					resp.Status,
					clientIP,
					buf.Client_port,
					serverIP,
					buf.Server_port,
				)

				for k, v := range resp.Headers {
					fmt.Printf("%s: %s\n", k, v)
				}

				fmt.Printf("\n%s\n\n", resp.Body)
			}
		}
	}
}
