package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/ssl_hook.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// struct for sslbuffer
type sslbuffer struct {
	Tid uint32
	Len uint32
	Buf [8192]byte
}

func main() {
	// only for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock %s", err)
	}

	// load objects
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading ebpf objects %s", err)
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

	for {
		record, err := rd.Read()
		if err != nil {
			log.Println("reading ringbuf %s", err)
			continue
		}

		var buf sslbuffer

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &buf)
		if err != nil {
			log.Println("copying into ssl buffer %s", err)
			continue
		}

		log.Printf("TID:%d LEN:%d \n %s \n", buf.Tid, buf.Len, string(buf.Buf[:buf.Len]))
	}
}
