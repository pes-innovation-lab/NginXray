package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang h3 ../../bpf/http3_headers.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	logger "nginxray/internal/logger"
	masking "nginxray/internal/masking"
	http1parser "nginxray/internal/parser"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	ngxOK   = 0
	ngxDone = -4
)

const (
	hookFieldLri = 1
)

const (
	tableOpInsert    = 0
	tableOpRefInsert = 1
	tableOpDuplicate = 2
)

type reqHeader struct {
	PidTgid  uint64
	TsNs     uint64
	ConnID   uint64
	ReqID    uint64
	Ret      int32
	NameLen  uint32
	ValueLen uint32
	Name     [128]byte
	Value    [512]byte
	IpLen    uint32
	Ip       [64]byte
}

type resHeader struct {
	PidTgid  uint64
	TsNs     uint64
	Conn     uint64
	Hook     uint32
	Dynamic  uint32
	Index    int64
	NameLen  uint32
	ValueLen uint32
	Name     [128]byte
	Value    [512]byte
	IpLen    uint32
	Ip       [64]byte
}

type tableEvent struct {
	PidTgid  uint64
	TsNs     uint64
	Conn     uint64
	Op       uint32
	Dynamic  uint32
	Index    int64
	NameLen  uint32
	ValueLen uint32
	Name     [128]byte
	Value    [512]byte
	IpLen    uint32
	Ip       [64]byte
}

type headerPair struct {
	Name  string
	Value string
}

var qpackStaticTable = []headerPair{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

type pendingRequest struct {
	fields  []headerPair
	ip      string
	pidTgid uint64
}

type pendingResponse struct {
	fields     []headerPair
	ip         string
	pidTgid    uint64
	base       int
	lastUpdate time.Time
}

var (
	qpackMu        sync.Mutex
	dynamicTables  = map[uint64][]headerPair{}
	pendingResp    = map[uint64]*pendingResponse{}
	pendingReq     = map[uint64]*pendingRequest{}
	flushIdleAfter = 50 * time.Millisecond
)

var (
	serverIP   string
	serverPort uint16
)

func resolveIndexed(conn uint64, dynamic bool, index int64, base int) (headerPair, bool) {
	if !dynamic {
		if index < 0 || int(index) >= len(qpackStaticTable) {
			return headerPair{}, false
		}
		return qpackStaticTable[index], true
	}

	qpackMu.Lock()
	defer qpackMu.Unlock()
	table := dynamicTables[conn]
	abs := base - 1 - int(index)
	if abs < 0 || abs >= len(table) {
		return headerPair{}, false
	}
	return table[abs], true
}

func resolveLive(conn uint64, dynamic bool, index int64) (headerPair, bool) {
	if !dynamic {
		if index < 0 || int(index) >= len(qpackStaticTable) {
			return headerPair{}, false
		}
		return qpackStaticTable[index], true
	}

	qpackMu.Lock()
	defer qpackMu.Unlock()
	table := dynamicTables[conn]
	abs := len(table) - 1 - int(index)
	if abs < 0 || abs >= len(table) {
		return headerPair{}, false
	}
	return table[abs], true
}

func tableInsert(conn uint64, name, value string) {
	qpackMu.Lock()
	dynamicTables[conn] = append(dynamicTables[conn], headerPair{name, value})
	qpackMu.Unlock()
}

func currentBase(conn uint64) int {
	qpackMu.Lock()
	defer qpackMu.Unlock()
	if pr, ok := pendingResp[conn]; ok {
		return pr.base
	}
	return len(dynamicTables[conn])
}

func appendRespField(conn uint64, ip string, pidTgid uint64, name, value string) {
	qpackMu.Lock()
	pr, ok := pendingResp[conn]
	if !ok {
		pr = &pendingResponse{
			ip:   ip,
			base: len(dynamicTables[conn]),
		}
		pendingResp[conn] = pr
	}
	pr.pidTgid = pidTgid
	pr.fields = append(pr.fields, headerPair{name, value})
	pr.lastUpdate = time.Now()
	qpackMu.Unlock()
}

func appendReqField(conn uint64, ip string, pidTgid uint64, name, value string) {
	qpackMu.Lock()
	pr, ok := pendingReq[conn]
	if !ok {
		pr = &pendingRequest{ip: ip}
		pendingReq[conn] = pr
	}
	pr.pidTgid = pidTgid
	pr.fields = append(pr.fields, headerPair{name, value})
	qpackMu.Unlock()
}

func takeReqFields(conn uint64) *pendingRequest {
	qpackMu.Lock()
	defer qpackMu.Unlock()
	pr := pendingReq[conn]
	delete(pendingReq, conn)
	return pr
}

func flushIdleResponses() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		qpackMu.Lock()
		var toEmit []struct {
			conn uint64
			pr   *pendingResponse
		}
		for conn, pr := range pendingResp {
			if now.Sub(pr.lastUpdate) >= flushIdleAfter {
				toEmit = append(toEmit, struct {
					conn uint64
					pr   *pendingResponse
				}{conn, pr})
				delete(pendingResp, conn)
			}
		}
		qpackMu.Unlock()

		for _, e := range toEmit {
			emitResponse(e.pr)
		}
	}
}

func splitHostPort(s string) (string, uint16) {
	if s == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return host, 0
	}
	return host, uint16(port)
}

func pidTid(pidTgid uint64) (uint32, uint32) {
	return uint32(pidTgid >> 32), uint32(pidTgid)
}

func addHeader(m map[string]string, name, value string) {
	sep := ", "
	if name == "cookie" {
		sep = "; "
	}
	if old, ok := m[name]; ok {
		m[name] = old + sep + value
	} else {
		m[name] = value
	}
}

func buildRequest(fields []headerPair) *http1parser.HTTPRequest {
	req := &http1parser.HTTPRequest{
		Version: "HTTP/3",
		Headers: make(map[string]string),
	}
	for _, f := range fields {
		switch f.Name {
		case ":method":
			req.Method = f.Value
		case ":path":
			req.Path = f.Value
		case ":authority":
			addHeader(req.Headers, "host", f.Value)
		case ":scheme":
		default:
			if len(f.Name) == 0 || f.Name[0] != ':' {
				addHeader(req.Headers, f.Name, f.Value)
			}
		}
	}
	return req
}

func buildResponse(fields []headerPair) *http1parser.HTTPResponse {
	resp := &http1parser.HTTPResponse{
		Version: "HTTP/3",
		Headers: make(map[string]string),
	}
	for _, f := range fields {
		if f.Name == ":status" {
			resp.Status = f.Value
			fmt.Sscanf(f.Value, "%d", &resp.Code)
		} else if len(f.Name) == 0 || f.Name[0] != ':' {
			addHeader(resp.Headers, f.Name, f.Value)
		}
	}
	return resp
}

func emitRequest(conn uint64) {
	pr := takeReqFields(conn)
	if pr == nil || len(pr.fields) == 0 {
		return
	}

	req := buildRequest(pr.fields)
	masking.MaskRequest(req)

	pid, tid := pidTid(pr.pidTgid)
	clientIP, clientPort := splitHostPort(pr.ip)

	eventTime := time.Now()
	timestamp := eventTime.Format(time.RFC3339Nano)

	logger.LogRequest(req, pid, tid, clientIP, clientPort, serverIP, serverPort, timestamp)
}

func emitResponse(pr *pendingResponse) {
	if len(pr.fields) == 0 {
		return
	}

	resp := buildResponse(pr.fields)
	masking.MaskResponse(resp)

	pid, tid := pidTid(pr.pidTgid)
	clientIP, clientPort := splitHostPort(pr.ip)

	eventTime := time.Now()
	timestamp := eventTime.Format(time.RFC3339Nano)

	logger.LogResponse(resp, pid, tid, clientIP, clientPort, serverIP, serverPort, timestamp)
}

func tableEventLoop(tableRd *ringbuf.Reader) {
	var tev tableEvent
	for {
		record, err := tableRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading table ringbuf: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &tev); err != nil {
			log.Printf("parsing table event: %v", err)
			continue
		}

		value := string(tev.Value[:tev.ValueLen])

		switch tev.Op {
		case tableOpInsert:
			name := string(tev.Name[:tev.NameLen])
			tableInsert(tev.Conn, name, value)

		case tableOpRefInsert:
			pair, ok := resolveLive(tev.Conn, tev.Dynamic != 0, tev.Index)
			if !ok {
				log.Printf("ref_insert: unresolved name index=%d dynamic=%v conn=%#x", tev.Index, tev.Dynamic != 0, tev.Conn)
				continue
			}
			tableInsert(tev.Conn, pair.Name, value)

		case tableOpDuplicate:
			pair, ok := resolveLive(tev.Conn, true, tev.Index)
			if !ok {
				log.Printf("duplicate: unresolved index=%d conn=%#x", tev.Index, tev.Conn)
				continue
			}
			tableInsert(tev.Conn, pair.Name, pair.Value)
		}
	}
}

func respEventLoop(respRd *ringbuf.Reader) {
	var rev resHeader
	for {
		record, err := respRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading resp ringbuf: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rev); err != nil {
			log.Printf("parsing resp event: %v", err)
			continue
		}

		ip := string(rev.Ip[:rev.IpLen])
		value := string(rev.Value[:rev.ValueLen])

		switch rev.Hook {
		case hookFieldLri:
			base := currentBase(rev.Conn)
			pair, ok := resolveIndexed(rev.Conn, rev.Dynamic != 0, rev.Index, base)
			if !ok {
				appendRespField(rev.Conn, ip, rev.PidTgid, "<unresolved lri index>", value)
				continue
			}
			appendRespField(rev.Conn, ip, rev.PidTgid, pair.Name, value)

		default:
			log.Printf("resp event: unexpected hook=%d conn=%#x", rev.Hook, rev.Conn)
		}
	}
}

func reqEventLoop(rd *ringbuf.Reader) {
	var ev reqHeader
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("shutting down")
				return
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		ip := string(ev.Ip[:ev.IpLen])

		switch ev.Ret {
		case ngxDone:
			if ev.NameLen > 0 || ev.ValueLen > 0 {
				name := string(ev.Name[:ev.NameLen])
				value := string(ev.Value[:ev.ValueLen])
				appendReqField(ev.ConnID, ip, ev.PidTgid, name, value)
			}
			emitRequest(ev.ConnID)

		case ngxOK:
			name := string(ev.Name[:ev.NameLen])
			value := string(ev.Value[:ev.ValueLen])
			appendReqField(ev.ConnID, ip, ev.PidTgid, name, value)

		default:
			pid, tid := pidTid(ev.PidTgid)
			log.Printf("pid=%d tid=%d req=%x ret=%d (unexpected)", pid, tid, ev.ReqID, ev.Ret)
		}
	}
}

func main() {
	binPath := flag.String("nginx-bin", "/usr/bin/nginx", "path to nginx binary to attach uprobes to")
	listenAddr := flag.String("listen", "", "nginx QUIC listen address (ip:port) reported as the server side of logged events")
	flag.Parse()

	if *listenAddr != "" {
		serverIP, serverPort = splitHostPort(*listenAddr)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	objs := h3Objects{}
	if err := loadH3Objects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	logger.Init()

	ex, err := link.OpenExecutable(*binPath)
	if err != nil {
		log.Fatalf("opening executable %s: %v", *binPath, err)
	}

	upEntry, err := ex.Uprobe("ngx_http_v3_parse_headers", objs.EntryParseHeaders, nil)
	if err != nil {
		log.Fatalf("attaching entry uprobe: %v", err)
	}
	defer upEntry.Close()

	upRet, err := ex.Uretprobe("ngx_http_v3_parse_headers", objs.RetParseHeaders, nil)
	if err != nil {
		log.Fatalf("attaching uretprobe: %v", err)
	}
	defer upRet.Close()

	upFieldLri, err := ex.Uprobe("ngx_http_v3_encode_field_lri", objs.EntryEncodeFieldLri, nil)
	if err != nil {
		log.Fatalf("attaching encode_field_lri uprobe: %v", err)
	}
	defer upFieldLri.Close()

	upInsert, err := ex.Uprobe("ngx_http_v3_insert", objs.EntryInsert, nil)
	if err != nil {
		log.Fatalf("attaching insert uprobe: %v", err)
	}
	defer upInsert.Close()

	upRefInsert, err := ex.Uprobe("ngx_http_v3_ref_insert", objs.EntryRefInsert, nil)
	if err != nil {
		log.Fatalf("attaching ref_insert uprobe: %v", err)
	}
	defer upRefInsert.Close()

	upDuplicate, err := ex.Uprobe("ngx_http_v3_duplicate", objs.EntryDuplicate, nil)
	if err != nil {
		log.Fatalf("attaching duplicate uprobe: %v", err)
	}
	defer upDuplicate.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	respRd, err := ringbuf.NewReader(objs.RespEvents)
	if err != nil {
		log.Fatalf("opening resp ringbuf reader: %v", err)
	}
	defer respRd.Close()

	tableRd, err := ringbuf.NewReader(objs.TableEvents)
	if err != nil {
		log.Fatalf("opening table ringbuf reader: %v", err)
	}
	defer tableRd.Close()

	log.Printf("attached to %s, reading events (ctrl-c to stop)", *binPath)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
		respRd.Close()
		tableRd.Close()
	}()

	go flushIdleResponses()
	go tableEventLoop(tableRd)
	go respEventLoop(respRd)

	reqEventLoop(rd)
}
