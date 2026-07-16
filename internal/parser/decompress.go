package http1parser

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

const maxDecompressedSize = 8 << 20

func DecodeResponseBody(resp *HTTPResponse) {
	if decoded, ok := decodeBody(resp.Body, resp.Headers["content-encoding"]); ok {
		resp.Body = decoded
	}
}

func DecodeRequestBody(req *HTTPRequest) {
	if decoded, ok := decodeBody(req.Body, req.Headers["content-encoding"]); ok {
		req.Body = decoded
	}
}

func decodeBody(body []byte, contentEncoding string) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" || enc == "identity" {
		return body, true
	}

	var r io.Reader
	switch enc {
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, false
		}
		defer gz.Close()
		r = gz
	case "br":
		r = brotli.NewReader(bytes.NewReader(body))
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer zr.Close()
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(body))
		}
	default:
		return body, false
	}

	limited := io.LimitReader(r, maxDecompressedSize+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return body, false
	}
	if len(out) > maxDecompressedSize {
		return out[:maxDecompressedSize], true
	}
	return out, true
}