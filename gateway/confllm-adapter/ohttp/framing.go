// framing.go — RFC 9292 Binary Representation of HTTP Messages 编解码（M8-1，技术方案 §5.5）。
//
// 实现范围（定版）：known-length 编码（OHTTP 仅要求 known-length；chunked/trailers 不支持）。
//
//	请求字段序：伪头 :method、:scheme、:authority、:path 置于最前；响应伪头 :status。
//	禁止字段：Host（由 :authority 承载）与连接类头（Connection/Keep-Alive/Proxy-*/TE/
//	Trailer/Transfer-Encoding/Upgrade）编解码两侧均剔除。
//
// 长度前缀（RFC 9292 §2.1 field-line-prefix 同款）：
//
//	0b0xxxxxxx = 0..126；0b10+14bit；0b110+21bit；0b111+28bit。
package ohttp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maxFieldLen 单字段/字段节/内容长度上限（2^28-1 为 RFC 9292 前缀上限；业务侧另受 body 限制约束）。
const maxFieldLen = 1<<28 - 1

// hopByHopHeaders 连接类头（bhttp 禁止携带）。
var hopByHopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
	"host": true, // Host 由 :authority 承载
}

// appendLenPrefix 追加 RFC 9292 长度前缀。
func appendLenPrefix(dst []byte, n int) ([]byte, error) {
	if n < 0 || n > maxFieldLen {
		return nil, fmt.Errorf("ohttp: 长度 %d 超出 RFC 9292 前缀上限", n)
	}
	switch {
	case n < 127:
		return append(dst, byte(n)), nil
	case n < 1<<14:
		return append(dst, byte(0x80|(n>>8)), byte(n)), nil
	case n < 1<<21:
		return append(dst, byte(0xC0|(n>>16)), byte(n>>8), byte(n)), nil
	default:
		return append(dst, byte(0xE0|(n>>24)), byte(n>>16), byte(n>>8), byte(n)), nil
	}
}

// readLenPrefix 解析长度前缀，返回 (值, 消耗字节数, 错误)。
func readLenPrefix(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("ohttp: 长度前缀截断")
	}
	fst := b[0]
	switch {
	case fst < 0x7F:
		return int(fst), 1, nil
	case fst&0xC0 == 0x80:
		if len(b) < 2 {
			return 0, 0, errors.New("ohttp: 14 位长度前缀截断")
		}
		return int(fst&0x3F)<<8 | int(b[1]), 2, nil
	case fst&0xE0 == 0xC0:
		if len(b) < 3 {
			return 0, 0, errors.New("ohttp: 21 位长度前缀截断")
		}
		return int(fst&0x1F)<<16 | int(b[1])<<8 | int(b[2]), 3, nil
	case fst&0xF0 == 0xE0:
		if len(b) < 4 {
			return 0, 0, errors.New("ohttp: 28 位长度前缀截断")
		}
		return int(fst&0x1F)<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3]), 4, nil
	default:
		return 0, 0, fmt.Errorf("ohttp: 非法长度前缀 0x%02x", fst)
	}
}

// encodeFieldSection 编码字段节（伪头在前、按序）。
func encodeFieldSection(fields [][2]string) ([]byte, error) {
	var sec []byte
	for _, f := range fields {
		var err error
		if sec, err = appendLenPrefix(sec, len(f[0])); err != nil {
			return nil, fmt.Errorf("ohttp: 字段名 %q 过长: %w", f[0], err)
		}
		sec = append(sec, f[0]...)
		if sec, err = appendLenPrefix(sec, len(f[1])); err != nil {
			return nil, fmt.Errorf("ohttp: 字段值 %q 过长: %w", f[1], err)
		}
		sec = append(sec, f[1]...)
	}
	return sec, nil
}

// decodeFieldSection 解析字段节。
func decodeFieldSection(b []byte) ([][2]string, error) {
	var fields [][2]string
	for len(b) > 0 {
		n, off, err := readLenPrefix(b)
		if err != nil {
			return nil, err
		}
		if off+n > len(b) {
			return nil, errors.New("ohttp: 字段名截断")
		}
		name := string(b[off : off+n])
		b = b[off+n:]
		v, off2, err := readLenPrefix(b)
		if err != nil {
			return nil, err
		}
		if off2+v > len(b) {
			return nil, errors.New("ohttp: 字段值截断")
		}
		fields = append(fields, [2]string{name, string(b[off2 : off2+v])})
		b = b[off2+v:]
	}
	return fields, nil
}

// EncodeBinaryHTTP 将 *http.Request 编码为 RFC 9292 known-length binary HTTP 消息
// （技术方案 §5.5 接口冻结基线签名）。
func EncodeBinaryHTTP(req *http.Request) ([]byte, error) {
	return EncodeBinaryHTTPReq(req)
}

// EncodeBinaryHTTPReq 请求编码的实现。
func EncodeBinaryHTTPReq(req *http.Request) ([]byte, error) {
	if req == nil {
		return nil, errors.New("ohttp: 请求为空")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	authority := req.Host
	if authority == "" && req.URL.Host != "" {
		authority = req.URL.Host
	}
	if authority == "" {
		return nil, errors.New("ohttp: 缺 authority（req.Host）")
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fields := [][2]string{
		{":method", method},
		{":scheme", scheme},
		{":authority", authority},
		{":path", path},
	}
	for k, vs := range req.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			fields = append(fields, [2]string{k, v})
		}
	}
	sec, err := encodeFieldSection(fields)
	if err != nil {
		return nil, err
	}
	var body []byte
	if req.Body != nil {
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, fmt.Errorf("ohttp: 读取请求体失败: %w", err)
		}
	}
	var out []byte
	if out, err = appendLenPrefix(nil, len(sec)); err != nil {
		return nil, err
	}
	out = append(out, sec...)
	if out, err = appendLenPrefix(out, len(body)); err != nil {
		return nil, err
	}
	out = append(out, body...)
	out = append(out, 0x00) // trailer 节长度 0（不支持 trailers）
	return out, nil
}

// DecodeBinaryHTTP 解析 RFC 9292 known-length binary HTTP 消息为 *http.Request。
func DecodeBinaryHTTP(b []byte) (*http.Request, error) {
	secLen, off, err := readLenPrefix(b)
	if err != nil {
		return nil, err
	}
	if off+secLen > len(b) {
		return nil, errors.New("ohttp: 字段节截断")
	}
	fields, err := decodeFieldSection(b[off : off+secLen])
	if err != nil {
		return nil, err
	}
	rest := b[off+secLen:]

	var method, scheme, authority, path string
	hdr := http.Header{}
	for i, f := range fields {
		switch f[0] {
		case ":method":
			method = f[1]
		case ":scheme":
			scheme = f[1]
		case ":authority":
			authority = f[1]
		case ":path":
			path = f[1]
		default:
			if strings.HasPrefix(f[0], ":") {
				return nil, fmt.Errorf("ohttp: 未知伪头 %q（位置 %d）", f[0], i)
			}
			if hopByHopHeaders[strings.ToLower(f[0])] {
				continue
			}
			hdr.Add(f[0], f[1])
		}
	}
	if method == "" || authority == "" || path == "" {
		return nil, fmt.Errorf("ohttp: 伪头缺失（method=%q authority=%q path=%q）", method, authority, path)
	}
	if scheme == "" {
		scheme = "https"
	}

	bodyLen, off3, err := readLenPrefix(rest)
	if err != nil {
		return nil, err
	}
	if off3+bodyLen > len(rest) {
		return nil, errors.New("ohttp: 内容截断")
	}
	body := rest[off3 : off3+bodyLen]
	rest = rest[off3+bodyLen:]
	// trailer 节长度（仅接受 0）。
	tl, off4, err := readLenPrefix(rest)
	if err != nil || off4+tl != len(rest) || tl != 0 {
		return nil, fmt.Errorf("ohttp: trailer 节非法（本实现仅支持无 trailer 的 known-length 消息）")
	}

	u := scheme + "://" + authority + path
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ohttp: 重建请求失败: %w", err)
	}
	req.Header = hdr
	return req, nil
}

// EncodeBinaryHTTPResponse 将 *http.Response 编码为 RFC 9292 known-length 消息（响应方向）。
func EncodeBinaryHTTPResponse(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.StatusCode == 0 {
		return nil, errors.New("ohttp: 响应为空")
	}
	fields := [][2]string{{":status", strconv.Itoa(resp.StatusCode)}}
	for k, vs := range resp.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			fields = append(fields, [2]string{k, v})
		}
	}
	sec, err := encodeFieldSection(fields)
	if err != nil {
		return nil, err
	}
	var body []byte
	if resp.Body != nil {
		if body, err = io.ReadAll(resp.Body); err != nil {
			return nil, fmt.Errorf("ohttp: 读取响应体失败: %w", err)
		}
	}
	var out []byte
	if out, err = appendLenPrefix(nil, len(sec)); err != nil {
		return nil, err
	}
	out = append(out, sec...)
	if out, err = appendLenPrefix(out, len(body)); err != nil {
		return nil, err
	}
	out = append(out, body...)
	out = append(out, 0x00)
	return out, nil
}

// DecodeBinaryHTTPResponse 解析 RFC 9292 known-length 响应消息。
func DecodeBinaryHTTPResponse(b []byte) (*http.Response, error) {
	secLen, off, err := readLenPrefix(b)
	if err != nil {
		return nil, err
	}
	if off+secLen > len(b) {
		return nil, errors.New("ohttp: 字段节截断")
	}
	fields, err := decodeFieldSection(b[off : off+secLen])
	if err != nil {
		return nil, err
	}
	rest := b[off+secLen:]

	var status int
	hdr := http.Header{}
	for _, f := range fields {
		if f[0] == ":status" {
			status, err = strconv.Atoi(f[1])
			if err != nil {
				return nil, fmt.Errorf("ohttp: :status 非法 %q", f[1])
			}
			continue
		}
		if strings.HasPrefix(f[0], ":") || hopByHopHeaders[strings.ToLower(f[0])] {
			continue
		}
		hdr.Add(f[0], f[1])
	}
	if status == 0 {
		return nil, errors.New("ohttp: 缺 :status 伪头")
	}
	bodyLen, off3, err := readLenPrefix(rest)
	if err != nil {
		return nil, err
	}
	if off3+bodyLen > len(rest) {
		return nil, errors.New("ohttp: 内容截断")
	}
	body := rest[off3 : off3+bodyLen]
	rest = rest[off3+bodyLen:]
	tl, off4, err := readLenPrefix(rest)
	if err != nil || off4+tl != len(rest) || tl != 0 {
		return nil, errors.New("ohttp: trailer 节非法")
	}
	return &http.Response{
		Status:     strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode: status,
		Header:     hdr,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}
