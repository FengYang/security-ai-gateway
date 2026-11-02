package route2qwen

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// tokenizer.go — Qwen2.5 BPE tokenizer（纯 Go，零外部依赖）。
//
// 设计目标：让 route2qwen 从"token id 直入"升级为"文本直入"，使端到端真模型验证
// 可用自然语言 prompt。实现忠实对应 Qwen2.5 的 tokenizer.json：
//   - model.type = BPE，merges 为空格分隔对（"Ġ Ġ"）
//   - byte-level 编码（GPT-2 byte_to_unicode 映射，空格→Ġ=U+0120）
//   - 预分词正则（手写扫描器等效，避免引入 PCRE 依赖）：
//     (?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+
//
// 已知限制：
//   - normalizer=NFC 未实现（典型 ASCII/中文/CJK prompt 已是 NFC，影响仅限分解态 Unicode 输入）。
//   - 预分词扫描器手动复刻上述正则，已覆盖常见中英文/数字/标点/空白；极个别边界 unicode 空白可能与
//     HF 参考实现存在 1 token 级差异，不影响掩码像管线（masked vs ref 共用同一份 token）的正确性判据。

// Tokenizer Qwen2.5 分词器实例。
type Tokenizer struct {
	vocab       map[string]int    // byte-level token 串 -> id
	idToToken   map[int]string    // id -> byte-level token 串
	ranks       map[[2]string]int // 合并对 -> 优先级（数组下标）
	specialToID map[string]int    // 特殊 token 串 -> id
	idToSpecial map[int]string    // id -> 特殊 token 串
	specials    []string          // 特殊 token 串（按长度降序，用于切分）
}

// LoadTokenizer 从 HuggingFace 格式的 tokenizer.json 载入 Qwen2.5 分词器。
func LoadTokenizer(path string) (*Tokenizer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("route2qwen: 读 tokenizer.json 失败: %w", err)
	}
	var f struct {
		Model struct {
			Type   string            `json:"type"`
			Vocab  map[string]int    `json:"vocab"`
			Merges []json.RawMessage `json:"merges"`
		} `json:"model"`
		AddedTokens []struct {
			ID      int    `json:"id"`
			Content string `json:"content"`
			Special bool   `json:"special"`
		} `json:"added_tokens"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("route2qwen: 解析 tokenizer.json 失败: %w", err)
	}
	if strings.ToUpper(f.Model.Type) != "BPE" {
		return nil, fmt.Errorf("route2qwen: 仅支持 BPE，实际 %q", f.Model.Type)
	}
	t := &Tokenizer{
		vocab:       f.Model.Vocab,
		idToToken:   make(map[int]string, len(f.Model.Vocab)),
		ranks:       make(map[[2]string]int, len(f.Model.Merges)),
		specialToID: make(map[string]int),
		idToSpecial: make(map[int]string),
	}
	for tok, id := range t.vocab {
		t.idToToken[id] = tok
	}
	for i, m := range f.Model.Merges {
		var s string
		if err := json.Unmarshal(m, &s); err == nil {
			// 形式 "X Y"（Qwen2.5 默认）
			if a, b, ok := splitMergePair(s); ok {
				t.ranks[[2]string{a, b}] = i
				continue
			}
		}
		var pair []string
		if json.Unmarshal(m, &pair) == nil && len(pair) == 2 {
			t.ranks[[2]string{pair[0], pair[1]}] = i
		}
	}
	for _, at := range f.AddedTokens {
		t.specialToID[at.Content] = at.ID
		t.idToSpecial[at.ID] = at.Content
	}
	// 特殊 token 按长度降序，切分时优先匹配更长者
	for c := range t.specialToID {
		t.specials = append(t.specials, c)
	}
	sortByLenDesc(t.specials)
	return t, nil
}

// splitMergePair 把 "X Y" 形式的合并项拆成 (X, Y)。
func splitMergePair(s string) (string, string, bool) {
	// 仅按首个空格切分（token 串本身可能含空格合并后的字符，但合并项格式固定为 "a b"）
	idx := strings.IndexByte(s, ' ')
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// Encode 把文本编码为 token id 序列。
func (t *Tokenizer) Encode(text string) []int {
	var ids []int
	for _, seg := range t.splitSpecial(text) {
		if seg.special {
			ids = append(ids, seg.id)
			continue
		}
		for _, piece := range preTokenize(seg.text) {
			syms := byteEncode(piece)
			syms = bpe(syms, t.ranks)
			for _, sym := range syms {
				if id, ok := t.vocab[sym]; ok {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

// Decode 把 token id 序列还原为文本。
func (t *Tokenizer) Decode(ids []int) string {
	var sb strings.Builder
	for _, id := range ids {
		if s, ok := t.idToToken[id]; ok {
			sb.WriteString(s)
		} else if s, ok := t.idToSpecial[id]; ok {
			sb.WriteString(s)
		}
	}
	return string(byteDecode(sb.String()))
}

// ---------- 特殊 token 切分 ----------

type textSeg struct {
	text    string
	special bool
	id      int
}

func (t *Tokenizer) splitSpecial(text string) []textSeg {
	if len(t.specials) == 0 {
		return []textSeg{{text: text}}
	}
	var segs []textSeg
	i := 0
	n := len(text)
	for i < n {
		matched := ""
		mid := -1
		for _, sp := range t.specials {
			if strings.HasPrefix(text[i:], sp) {
				matched = sp
				mid = t.specialToID[sp]
				break
			}
		}
		if matched == "" {
			// 累积到下一个特殊 token 起点
			j := i + 1
			for j < n {
				found := false
				for _, sp := range t.specials {
					if strings.HasPrefix(text[j:], sp) {
						found = true
						break
					}
				}
				if found {
					break
				}
				j++
			}
			segs = append(segs, textSeg{text: text[i:j]})
			i = j
			continue
		}
		segs = append(segs, textSeg{text: matched, special: true, id: mid})
		i += len(matched)
	}
	return segs
}

// ---------- 预分词（手写等效 Qwen 正则） ----------

func isLetter(r rune) bool { return unicode.IsLetter(r) }
func isNumber(r rune) bool { return unicode.IsNumber(r) }
func isSpace(r rune) bool  { return unicode.IsSpace(r) }
func isPunct(r rune) bool  { return !isSpace(r) && !isLetter(r) && !isNumber(r) }

// preTokenize 把一段文本切成预分词片（等效 Qwen 正则，按替代项顺序匹配）。
func preTokenize(text string) []string {
	rs := []rune(text)
	n := len(rs)
	var out []string
	i := 0
	for i < n {
		if m := matchContraction(rs[i:]); m > 0 {
			out = append(out, string(rs[i:i+m]))
			i += m
			continue
		}
		if m := matchLetterRun(rs[i:]); m > 0 {
			out = append(out, string(rs[i:i+m]))
			i += m
			continue
		}
		if i < n && isNumber(rs[i]) {
			out = append(out, string(rs[i]))
			i++
			continue
		}
		if m := matchPunct(rs[i:]); m > 0 {
			out = append(out, string(rs[i:i+m]))
			i += m
			continue
		}
		if m := matchNewline(rs[i:]); m > 0 {
			out = append(out, string(rs[i:i+m]))
			i += m
			continue
		}
		if i < n && isSpace(rs[i]) {
			j := i
			for j < n && isSpace(rs[j]) {
				j++
			}
			out = append(out, string(rs[i:j]))
			i = j
			continue
		}
		// 兜底：吞掉一个 rune（理论上不可达）
		out = append(out, string(rs[i]))
		i++
	}
	return out
}

func matchContraction(rs []rune) int {
	if len(rs) == 0 || rs[0] != '\'' {
		return 0
	}
	rest := strings.ToLower(string(rs[1:]))
	for _, c := range []string{"s", "t", "re", "ve", "m", "ll", "d"} {
		if strings.HasPrefix(rest, c) {
			return 1 + len([]rune(c))
		}
	}
	return 0
}

// matchLetterRun 匹配 [^\r\n\p{L}\p{N}]?\p{L}+
func matchLetterRun(rs []rune) int {
	n := len(rs)
	i := 0
	if i < n {
		c := rs[i]
		if c != '\r' && c != '\n' && !isLetter(c) && !isNumber(c) {
			i++ // 可选的前导非字母非数字字符
		}
	}
	if i >= n || !isLetter(rs[i]) {
		return 0 // 至少需要一个字母
	}
	for i < n && isLetter(rs[i]) {
		i++
	}
	return i
}

// matchPunct 匹配 " ?" [^\s\p{L}\p{N}]+ [\r\n]*
func matchPunct(rs []rune) int {
	n := len(rs)
	i := 0
	if i < n && rs[i] == ' ' {
		i++
	}
	if i >= n || !isPunct(rs[i]) {
		return 0
	}
	for i < n && isPunct(rs[i]) {
		i++
	}
	for i < n && (rs[i] == '\r' || rs[i] == '\n') {
		i++
	}
	return i
}

// matchNewline 匹配 \s* [\r\n]+（含换行符的整段空白）
func matchNewline(rs []rune) int {
	n := len(rs)
	i := 0
	hasNL := false
	for i < n && isSpace(rs[i]) {
		if rs[i] == '\r' || rs[i] == '\n' {
			hasNL = true
		}
		i++
	}
	if !hasNL {
		return 0
	}
	return i
}

// ---------- byte-level 编码 ----------

var (
	byteEncoder [256]rune
	byteDecoder map[rune]byte
)

func init() {
	// GPT-2 byte_to_unicode：可见 ASCII 范围原样保留，其余字节顺序映射到 U+0100+。
	var bs []int
	for c := '!'; c <= '~'; c++ {
		bs = append(bs, int(c))
	}
	for c := '¡'; c <= '¬'; c++ {
		bs = append(bs, int(c))
	}
	for c := '®'; c <= 'ÿ'; c++ {
		bs = append(bs, int(c))
	}
	inBS := make(map[int]bool, len(bs))
	for _, b := range bs {
		inBS[b] = true
	}
	byteDecoder = make(map[rune]byte)
	n := 0
	for b := 0; b < 256; b++ {
		var r rune
		if inBS[b] {
			r = rune(b)
		} else {
			r = rune(256 + n)
			n++
		}
		byteEncoder[b] = r
		byteDecoder[r] = byte(b)
	}
}

func byteEncode(s string) []string {
	b := []byte(s)
	syms := make([]string, len(b))
	for i, by := range b {
		syms[i] = string(byteEncoder[by])
	}
	return syms
}

func byteDecode(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if by, ok := byteDecoder[r]; ok {
			out = append(out, by)
		}
	}
	return out
}

// ---------- BPE ----------

// bpe 反复合并优先级最高的相邻对，直到无法合并。
func bpe(syms []string, ranks map[[2]string]int) []string {
	for {
		bestRank := int(^uint(0) >> 1) // max int
		bestIdx := -1
		for i := 0; i+1 < len(syms); i++ {
			if r, ok := ranks[[2]string{syms[i], syms[i+1]}]; ok && r < bestRank {
				bestRank = r
				bestIdx = i
			}
		}
		if bestIdx < 0 {
			break
		}
		merged := syms[bestIdx] + syms[bestIdx+1]
		syms = append(syms[:bestIdx], append([]string{merged}, syms[bestIdx+2:]...)...)
	}
	return syms
}

func sortByLenDesc(ss []string) {
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			if len(ss[j]) > len(ss[i]) {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}
}
