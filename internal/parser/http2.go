package http1parser
import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const PrefaceLen = len(ClientPreface)

// Protocol classification 
const (
	ProtoUnknown = 0
	ProtoHTTP1   = 1
	ProtoHTTP2   = 2
)

func DetectProto(requestBytes []byte) int {
	pre := []byte(ClientPreface)
	if len(requestBytes) >= len(pre) {
		if bytes.HasPrefix(requestBytes, pre) {
			return ProtoHTTP2
		}
		return ProtoHTTP1
	}
	if bytes.HasPrefix(pre, requestBytes) {
		return ProtoUnknown // still could become h2; wait for more bytes
	}
	return ProtoHTTP1
}

const (
	frameData         = 0x0
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePushPromise  = 0x5
	framePing         = 0x6
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8
	frameContinuation = 0x9
)


const (
	flagEndStream  = 0x1  // DATA, HEADERS
	flagEndHeaders = 0x4  // HEADERS, CONTINUATION, PUSH_PROMISE
	flagPadded     = 0x8  // DATA, HEADERS, PUSH_PROMISE
	flagPriority   = 0x20 // HEADERS
)

const (
	frameHeaderLen = 9
	maxFrameSize = (1 << 24) - 1
	maxHeaderBlock = 256 * 1024
	maxBodyPerStream = 8 * 1024 * 1024
	maxStreams = 4096
	allowedTableSize = 65536
	maxDirBuffer = maxFrameSize + frameHeaderLen
)

type CompletedRequest struct {
	StreamID      uint32
	Request       *HTTPRequest
	BodyTruncated bool
}

type CompletedResponse struct {
	StreamID      uint32
	Response      *HTTPResponse
	BodyTruncated bool
}

type h2Stream struct {
	headers   []hpack.HeaderField
	gotHeader bool
	body      bytes.Buffer
	bodyTrunc bool
}

// finished pairs a completed stream with its id, queued for the caller.
type finished struct {
	streamID uint32
	st       *h2Stream
}

type h2Direction struct {
	isRequest bool
	dec       *hpack.Decoder
	buf       []byte 
	streams   map[uint32]*h2Stream
	done      []finished 

	poisoned bool
	reason   string


	assembling bool
	contStream uint32
	target     uint32
	endStream  bool
	frag       []byte
}

func (d *h2Direction) init(isRequest bool) {
	d.isRequest = isRequest
	d.streams = make(map[uint32]*h2Stream)
	d.dec = hpack.NewDecoder(4096, nil) 
	d.dec.SetAllowedMaxDynamicTableSize(allowedTableSize)
}

func (d *h2Direction) poison(reason string) {
	if d.poisoned {
		return
	}
	d.poisoned = true
	d.reason = reason
	d.streams = nil
	d.buf = nil
	d.frag = nil
	d.assembling = false
}

type HTTP2Conn struct {
	req  h2Direction
	resp h2Direction
}

func NewHTTP2Conn() *HTTP2Conn {
	c := &HTTP2Conn{}
	c.req.init(true)
	c.resp.init(false)
	return c
}

func (c *HTTP2Conn) Poisoned() bool { return c.req.poisoned || c.resp.poisoned }

func (c *HTTP2Conn) PoisonReason() string {
	if c.req.reason != "" {
		return "request: " + c.req.reason
	}
	if c.resp.reason != "" {
		return "response: " + c.resp.reason
	}
	return ""
}

func (c *HTTP2Conn) FeedRequest(data []byte, truncated bool) []CompletedRequest {
	if truncated {
		c.req.poison("capture gap / truncated read")
	}
	c.req.feed(data)
	if len(c.req.done) == 0 {
		return nil
	}
	out := make([]CompletedRequest, 0, len(c.req.done))
	for _, f := range c.req.done {
		req, trunc := buildRequest(f.st)
		out = append(out, CompletedRequest{StreamID: f.streamID, Request: req, BodyTruncated: trunc})
	}
	c.req.done = c.req.done[:0]
	return out
}

func (c *HTTP2Conn) FeedResponse(data []byte, truncated bool) []CompletedResponse {
	if truncated {
		c.resp.poison("capture gap / truncated read")
	}
	c.resp.feed(data)
	if len(c.resp.done) == 0 {
		return nil
	}
	out := make([]CompletedResponse, 0, len(c.resp.done))
	for _, f := range c.resp.done {
		resp, trunc := buildResponse(f.st)
		out = append(out, CompletedResponse{StreamID: f.streamID, Response: resp, BodyTruncated: trunc})
	}
	c.resp.done = c.resp.done[:0]
	return out
}

func (d *h2Direction) feed(data []byte) {
	if d.poisoned {
		return
	}
	if len(d.buf)+len(data) > maxDirBuffer {
		d.poison("direction buffer overflow")
		return
	}
	d.buf = append(d.buf, data...) 
	d.drain()
}

// consuming every complete frame currently buffered
func (d *h2Direction) drain() {
	for !d.poisoned {
		if len(d.buf) < frameHeaderLen {
			break
		}
		length := uint32(d.buf[0])<<16 | uint32(d.buf[1])<<8 | uint32(d.buf[2])
		if length > maxFrameSize { // unreachable given 24-bit field, but explicit
			d.poison("frame length exceeds max")
			return
		}
		total := frameHeaderLen + int(length)
		if len(d.buf) < total {
			break // whole frame not here yet; wait for more bytes
		}
		ftype := d.buf[3]
		flags := d.buf[4]
		streamID := (uint32(d.buf[5])<<24 | uint32(d.buf[6])<<16 |
			uint32(d.buf[7])<<8 | uint32(d.buf[8])) & 0x7fffffff // clear reserved bit
		payload := d.buf[frameHeaderLen:total]

		d.handleFrame(ftype, flags, streamID, payload)
		if d.poisoned { 
			return
		}

		d.buf = d.buf[total:]
	}
	// Compact away dead capacity left by forward-slicing.
	if len(d.buf) == 0 {
		d.buf = d.buf[:0]
	} else if cap(d.buf) > 2*len(d.buf)+4096 {
		d.buf = append([]byte(nil), d.buf...)
	}
}

func (d *h2Direction) handleFrame(ftype, flags uint8, streamID uint32, payload []byte) {
	if d.assembling {
		if ftype != frameContinuation || streamID != d.contStream {
			d.poison("frame interleaved inside header block")
			return
		}
	}

	switch ftype {
	case frameHeaders:
		d.onHeaders(flags, streamID, payload)
	case frameContinuation:
		d.onContinuation(flags, streamID, payload)
	case frameData:
		d.onData(flags, streamID, payload)
	case framePushPromise:
		d.onPushPromise(flags, streamID, payload)
	case frameRSTStream:
		if d.streams != nil {
			delete(d.streams, streamID)
		}
	case frameSettings, framePriority, framePing, frameGoAway, frameWindowUpdate:
		
	default:
		// Unknown 
	}
}

func stripPadding(p []byte) (out []byte, ok bool) {
	if len(p) < 1 {
		return nil, false
	}
	padLen := int(p[0])
	p = p[1:]
	if padLen > len(p) {
		return nil, false
	}
	return p[:len(p)-padLen], true
}

func (d *h2Direction) onHeaders(flags uint8, streamID uint32, payload []byte) {
	if streamID == 0 {
		d.poison("HEADERS on stream 0")
		return
	}
	p := payload
	if flags&flagPadded != 0 {
		var ok bool
		if p, ok = stripPadding(p); !ok {
			d.poison("bad HEADERS padding")
			return
		}
	}
	if flags&flagPriority != 0 {
		if len(p) < 5 { // 4-byte stream dependency + 1-byte weight
			d.poison("HEADERS priority underflow")
			return
		}
		p = p[5:]
	}
	d.beginBlock(streamID, streamID, flags&flagEndStream != 0, p, flags&flagEndHeaders != 0)
}

func (d *h2Direction) onContinuation(flags uint8, streamID uint32, payload []byte) {
	if !d.assembling {
		d.poison("CONTINUATION without HEADERS")
		return
	}
	if streamID != d.contStream { // also caught by the gate; defensive
		d.poison("CONTINUATION on wrong stream")
		return
	}
	d.frag = append(d.frag, payload...)
	if len(d.frag) > maxHeaderBlock {
		d.poison("header block too large (continuation flood?)")
		return
	}
	if flags&flagEndHeaders != 0 {
		d.finishBlock()
	}
}

func (d *h2Direction) onPushPromise(flags uint8, streamID uint32, payload []byte) {
	p := payload
	if flags&flagPadded != 0 {
		var ok bool
		if p, ok = stripPadding(p); !ok {
			d.poison("bad PUSH_PROMISE padding")
			return
		}
	}
	if len(p) < 4 {
		d.poison("PUSH_PROMISE underflow")
		return
	}
	promised := (uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])) & 0x7fffffff
	p = p[4:]
	d.beginBlock(streamID, promised, false, p, flags&flagEndHeaders != 0)
}

func (d *h2Direction) beginBlock(contStream, target uint32, endStream bool, frag []byte, endHeaders bool) {
	d.assembling = true
	d.contStream = contStream
	d.target = target
	d.endStream = endStream
	d.frag = append(d.frag[:0], frag...)
	if len(d.frag) > maxHeaderBlock {
		d.poison("header block too large")
		return
	}
	if endHeaders {
		d.finishBlock()
	}
}

func (d *h2Direction) finishBlock() {
	fields, err := d.dec.DecodeFull(d.frag)
	d.assembling = false
	d.frag = d.frag[:0]
	if err != nil {
		d.poison("hpack decode: " + err.Error())
		return
	}

	st := d.streams[d.target]
	if st == nil {
		if len(d.streams) >= maxStreams {
			return // bound memory, drop this stream
		}
		st = &h2Stream{}
		d.streams[d.target] = st
	}
	if !st.gotHeader {
		st.headers = fields
		st.gotHeader = true
	} else {
		st.headers = append(st.headers, fields...) // trailers
	}

	if d.endStream {
		d.complete(d.target, st)
	}
}

func (d *h2Direction) onData(flags uint8, streamID uint32, payload []byte) {
	if streamID == 0 {
		d.poison("DATA on stream 0")
		return
	}
	p := payload
	if flags&flagPadded != 0 {
		var ok bool
		if p, ok = stripPadding(p); !ok {
			p = nil
		}
	}
	st := d.streams[streamID]
	if st == nil {
		if len(d.streams) >= maxStreams {
			return
		}
		st = &h2Stream{}
		d.streams[streamID] = st
	}
	if len(p) > 0 && !st.bodyTrunc {
		room := maxBodyPerStream - st.body.Len()
		if room <= 0 {
			st.bodyTrunc = true
		} else if len(p) > room {
			st.body.Write(p[:room])
			st.bodyTrunc = true
		} else {
			st.body.Write(p)
		}
	}
	if flags&flagEndStream != 0 {
		d.complete(streamID, st)
	}
}

func (d *h2Direction) complete(streamID uint32, st *h2Stream) {
	if !st.gotHeader {
		delete(d.streams, streamID)
		return
	}
	d.done = append(d.done, finished{streamID: streamID, st: st})
	delete(d.streams, streamID)
}

func buildRequest(st *h2Stream) (*HTTPRequest, bool) {
	req := &HTTPRequest{
		Version: "HTTP/2",
		Headers: make(map[string]string),
		Body:    st.body.Bytes(),
	}
	for _, f := range st.headers {
		switch f.Name {
		case ":method":
			req.Method = f.Value
		case ":path":
			req.Path = f.Value
		case ":authority":
			addHeader(req.Headers, "host", f.Value) // :authority is the h2 Host
		case ":scheme":
			// omitted for parity with the h1 output
		default:
			if !strings.HasPrefix(f.Name, ":") {
				addHeader(req.Headers, f.Name, f.Value)
			}
		}
	}
	return req, st.bodyTrunc
}

func buildResponse(st *h2Stream) (*HTTPResponse, bool) {
	resp := &HTTPResponse{
		Version: "HTTP/2",
		Headers: make(map[string]string),
		Body:    st.body.Bytes(),
	}
	for _, f := range st.headers {
		if f.Name == ":status" {
			resp.Status = f.Value 
			fmt.Sscanf(f.Value, "%d", &resp.Code)
		} else if !strings.HasPrefix(f.Name, ":") {
			addHeader(resp.Headers, f.Name, f.Value)
		}
	}
	return resp, st.bodyTrunc
}

func addHeader(m map[string]string, name, value string) {
	sep := ", "
	if name == "cookie" {
		sep = "; " // h2 may split cookie into several fields 
	}
	if old, ok := m[name]; ok {
		m[name] = old + sep + value
	} else {
		m[name] = value
	}
}
