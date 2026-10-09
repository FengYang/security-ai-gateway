// Package main — 图形验证码（§6.11 / §10.3 C）。
//
// 零新增依赖：image/png 手绘 5×7 点阵字符 + 噪点/干扰线。
// 答案存内存（TTL 5min，一次性，单副本约束内有效）；同 IP 签发限流（默认 30 次/h）。
//
// 端点：GET /v1/adminext/captcha（Console 内部，authMiddleware）→ {captcha_id, image}。
// 校验：register/login/password-reset 携带 captcha_id + captcha_code（§6.2）。
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	"strings"
	"sync"
	"time"
)

// 验证码字符集（排除易混字符 0/O/1/I/L）。
const captchaCharset = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

const (
	captchaLength = 4
	captchaScale  = 5 // 点阵放大倍数
	captchaCharW  = 5 // 字模宽（列）
	captchaCharH  = 7 // 字模高（行）
	captchaGap    = 1 // 字符间隔（列）
)

// errCaptchaRateLimited 签发限流。
var errCaptchaRateLimited = errors.New("tenant: captcha issue rate limited")

// captchaItem 单条验证码。
type captchaItem struct {
	code      string
	expiresAt time.Time
}

// captchaStore 验证码内存存储（含签发限流）。
type captchaStore struct {
	mu      sync.Mutex
	items   map[string]*captchaItem
	ipHits  map[string][]int64 // IP → 签发时刻（小时窗口限流）
	ttl     time.Duration
	ipLimit int
}

// newCaptchaStore 构造验证码存储（ttlMin 答案 TTL 分钟；ipLimitPerHour 同 IP 小时上限）。
func newCaptchaStore(ttlMin, ipLimitPerHour int) *captchaStore {
	return &captchaStore{
		items:   make(map[string]*captchaItem),
		ipHits:  make(map[string][]int64),
		ttl:     time.Duration(ttlMin) * time.Minute,
		ipLimit: ipLimitPerHour,
	}
}

// allowIP 记录并检查同 IP 签发频率（小时窗口，超过 → false）。
func (s *captchaStore) allowIP(ip string) bool {
	now := time.Now().Unix()
	cutoff := now - 3600
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.ipHits[ip][:0]
	for _, t := range s.ipHits[ip] {
		if t > cutoff {
			kept = append(kept, t)
		}
	}
	if len(kept) >= s.ipLimit {
		s.ipHits[ip] = kept
		return false
	}
	s.ipHits[ip] = append(kept, now)
	return true
}

// Issue 生成验证码：返回 (id, dataURL)。同 IP 超限 → errCaptchaRateLimited。
func (s *captchaStore) Issue(ip string) (id, imageDataURL string, err error) {
	if !s.allowIP(ip) {
		return "", "", errCaptchaRateLimited
	}
	code, err := randomCaptchaCode(captchaLength)
	if err != nil {
		return "", "", err
	}
	id, err = randomToken(16)
	if err != nil {
		return "", "", err
	}
	pngBytes, err := renderCaptchaPNG(code)
	if err != nil {
		return "", "", err
	}

	s.mu.Lock()
	s.gcLocked(time.Now())
	s.items[id] = &captchaItem{code: code, expiresAt: time.Now().Add(s.ttl)}
	s.mu.Unlock()

	return id, "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes), nil
}

// Verify 校验并**一次性消费**（无论对错都删除，防爆破）；大小写不敏感。
func (s *captchaStore) Verify(id, code string) bool {
	if id == "" || code == "" {
		return false
	}
	s.mu.Lock()
	it, ok := s.items[id]
	if ok {
		delete(s.items, id)
	}
	s.mu.Unlock()
	if !ok || time.Now().After(it.expiresAt) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(code), it.code)
}

// gcLocked 清理过期项（调用方需持锁）。
func (s *captchaStore) gcLocked(now time.Time) {
	for k, it := range s.items {
		if now.After(it.expiresAt) {
			delete(s.items, k)
		}
	}
}

// randomCaptchaCode 生成 n 位随机验证码（crypto/rand）。
func randomCaptchaCode(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(captchaCharset)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = captchaCharset[idx.Int64()]
	}
	return string(out), nil
}

// renderCaptchaPNG 绘制验证码 PNG（白底黑字 + 灰噪点 + 干扰线）。
func renderCaptchaPNG(code string) ([]byte, error) {
	const pad = 8
	chW := captchaCharW * captchaScale
	chH := captchaCharH * captchaScale
	gap := captchaGap * captchaScale
	width := pad*2 + len(code)*chW + (len(code)-1)*gap
	height := pad*2 + chH

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.White}, image.Point{}, draw.Src)

	// 字符
	for i, ch := range code {
		glyph, ok := captchaFont[ch]
		if !ok {
			continue
		}
		ox := pad + i*(chW+gap)
		oy := pad
		for col := 0; col < captchaCharW; col++ {
			bits := glyph[col]
			for row := 0; row < captchaCharH; row++ {
				if bits&(1<<uint(row)) == 0 {
					continue
				}
				for dy := 0; dy < captchaScale; dy++ {
					for dx := 0; dx < captchaScale; dx++ {
						img.Set(ox+col*captchaScale+dx, oy+row*captchaScale+dy, color.Black)
					}
				}
			}
		}
	}

	// 噪点
	noiseColor := color.RGBA{R: 160, G: 160, B: 160, A: 255}
	for i := 0; i < width*height/32; i++ {
		img.Set(randInt(width), randInt(height), noiseColor)
	}
	// 干扰线（2 条）
	lineColor := color.RGBA{R: 120, G: 120, B: 120, A: 255}
	for l := 0; l < 2; l++ {
		drawLine(img, randInt(width), randInt(height), randInt(width), randInt(height), lineColor)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// randInt 返回 [0,n) 随机整数（n<=0 返回 0）。
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// drawLine Bresenham 直线（用于干扰线）。
func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	dx := abs(x1 - x0)
	dy := abs(y1 - y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx - dy
	for {
		img.Set(x0, y0, c)
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x0 += sx
		}
		if e2 < dx {
			err += dx
			y0 += sy
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// captchaFont 5×7 点阵字模（列式，每列 bit0=顶行…bit6=底行）。
var captchaFont = map[rune][5]byte{
	'2': {0x42, 0x61, 0x51, 0x49, 0x46},
	'3': {0x21, 0x41, 0x45, 0x4B, 0x31},
	'4': {0x18, 0x14, 0x12, 0x7F, 0x10},
	'5': {0x27, 0x45, 0x45, 0x45, 0x39},
	'6': {0x3C, 0x4A, 0x49, 0x49, 0x30},
	'7': {0x01, 0x71, 0x09, 0x05, 0x03},
	'8': {0x36, 0x49, 0x49, 0x49, 0x36},
	'9': {0x06, 0x49, 0x49, 0x29, 0x1E},
	'A': {0x7E, 0x11, 0x11, 0x11, 0x7E},
	'B': {0x7F, 0x49, 0x49, 0x49, 0x36},
	'C': {0x3E, 0x41, 0x41, 0x41, 0x22},
	'D': {0x7F, 0x41, 0x41, 0x22, 0x1C},
	'E': {0x7F, 0x49, 0x49, 0x49, 0x41},
	'F': {0x7F, 0x09, 0x09, 0x09, 0x01},
	'G': {0x3E, 0x41, 0x49, 0x49, 0x7A},
	'H': {0x7F, 0x08, 0x08, 0x08, 0x7F},
	'J': {0x20, 0x40, 0x41, 0x3F, 0x01},
	'K': {0x7F, 0x08, 0x14, 0x22, 0x41},
	'M': {0x7F, 0x02, 0x0C, 0x02, 0x7F},
	'N': {0x7F, 0x04, 0x08, 0x10, 0x7F},
	'P': {0x7F, 0x09, 0x09, 0x09, 0x06},
	'Q': {0x3E, 0x41, 0x51, 0x21, 0x5E},
	'R': {0x7F, 0x09, 0x19, 0x29, 0x46},
	'S': {0x46, 0x49, 0x49, 0x49, 0x31},
	'T': {0x01, 0x01, 0x7F, 0x01, 0x01},
	'U': {0x3F, 0x40, 0x40, 0x40, 0x3F},
	'V': {0x1F, 0x20, 0x40, 0x20, 0x1F},
	'W': {0x3F, 0x40, 0x38, 0x40, 0x3F},
	'X': {0x63, 0x14, 0x08, 0x14, 0x63},
	'Y': {0x07, 0x08, 0x70, 0x08, 0x07},
	'Z': {0x61, 0x51, 0x49, 0x45, 0x43},
}
