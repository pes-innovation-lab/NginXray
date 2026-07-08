package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/ssl_hook.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	http1parser "nginxray/internal/parser"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// connection tracks per-SSL-connection reassembly buffers
type connection struct {
	request_buffer  bytes.Buffer
	response_buffer bytes.Buffer
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

	// get ssl executable
	path, err := findLibSSLPath()
	if err != nil {
		log.Fatalf("finding openssl path :%s", err)
	}
	exec, err := link.OpenExecutable(path)
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
			conn.response_buffer.Write(buf.Buf[:buf.Len])
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
