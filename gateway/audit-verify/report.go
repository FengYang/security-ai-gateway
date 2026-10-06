package auditverify

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Report 验证报告（JSON）：可归档给第三方/审计，随报告固化本轮验证的口径与已知局限。
//
// 链文件指纹（ChainSHA256/ChainBytes/ChainLines）用于防"报告与链不是同一份"——
// 第三方复核时应重算指纹比对。注意：生成报告会**整读一次链文件**，
// 窗口抽样模式下即放弃 O(窗口) 的 I/O 收益（属归档动作的取舍，README 已说明）。
type Report struct {
	Tool        string   `json:"tool"`
	GeneratedAt string   `json:"generated_at"`
	ChainFile   string   `json:"chain_file"`
	ChainBytes  int64    `json:"chain_bytes"`
	ChainLines  int      `json:"chain_lines"`
	ChainSHA256 string   `json:"chain_sha256"`
	Result      *Result  `json:"result"`
	Limitations []string `json:"limitations"`
}

// reportLimitations 报告的已知局限（固定声明，避免"报告看起来像背书"）。
var reportLimitations = []string{
	"哈希链校验只覆盖“内容与链序是否被改动”；不验证事件时间戳真伪（需 TST 的 TSA 验签或外部公证）。",
	"不覆盖“整链被整体替换成另一条自洽链”的场景（需外部可信锚点副本比对）。",
	"TST 仅做 imprint 一致性校验（imprint == Hash(chain_hash)，算法随 TST.algorithm 分派）；令牌签名验签需 TSA 根证书，属外部条件。",
}

// windowLimitation 窗口抽样模式附加局限。
const windowLimitation = "窗口抽样模式：窗口之外的事件未参与校验；若已提前停止读取（remain_after=-1），无法判定截断。"

// NewReport 组装报告并计算链文件指纹（SHA-256/字节数/非空行数）。
func NewReport(chainPath string, res *Result) (*Report, error) {
	sum, size, lines, err := fingerprint(chainPath)
	if err != nil {
		return nil, err
	}
	limitations := append([]string{}, reportLimitations...)
	if res.Scoped {
		limitations = append(limitations, windowLimitation)
	}
	return &Report{
		Tool:        "audit-verify",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ChainFile:   chainPath,
		ChainBytes:  size,
		ChainLines:  lines,
		ChainSHA256: sum,
		Result:      res,
		Limitations: limitations,
	}, nil
}

// WriteReport 落盘报告（JSON，缩进便于人读；报告不含敏感内容）。
func WriteReport(path string, rep *Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("报告序列化失败: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("报告写入失败 %s: %w", path, err)
	}
	return nil
}

// AnchorRecordFrom 由验证结果构造锚点记录。
//
// events 取**绝对**位置（窗口尾条序号+1），因此窗口抽样产出的锚点仍是合法的
// "某前缀长度的链尾哈希"，可被后续校验按前缀位置直接使用。
func AnchorRecordFrom(res *Result, timestampNS int64) (AnchorRecord, error) {
	if res.LastHash == "" {
		return AnchorRecord{}, errors.New("无可锚定内容：本次未校验任何事件（链为空或窗口内无事件）")
	}
	return AnchorRecord{
		Timestamp: timestampNS,
		Events:    res.ScopeLastIndex + 1,
		ChainHash: res.LastHash,
	}, nil
}

// EmitAnchor 追加一条锚点记录（WORM 只追加；与两端锚点文件同格式）。
func EmitAnchor(path string, rec AnchorRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("锚点记录序列化失败: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("打开锚点文件失败 %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("锚点写入失败 %s: %w", path, err)
	}
	return nil
}

// fingerprint 流式计算链文件 SHA-256 / 字节数 / 非空行数（不整份载入内存）。
func fingerprint(path string) (string, int64, int, error) {
	f, err := openFile(path)
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()
	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(f, h)) // TeeReader：读过的字节全部进摘要
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	lines := 0
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			lines++
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, 0, fmt.Errorf("读取链内容失败: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		return "", 0, 0, fmt.Errorf("读取文件信息失败: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), info.Size(), lines, nil
}
