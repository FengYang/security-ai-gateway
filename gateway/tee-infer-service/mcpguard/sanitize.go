package mcpguard

import (
	"encoding/hex"
	"encoding/json"
	"crypto/sha256"
	"fmt"

	"security-ai-gateway/gateway/mcpsec"
)

// sanitizeParams 按工具 schema 声明的敏感字段三态处理参数（S-5），返回脱敏后副本。
// 规则：strip→移除字段；block→含敏感即返回错误（拒绝）；mask→值替换为 [已脱敏]。
// 不修改入参（只读拷贝），保证调用方/审计不接触敏感明文编排结果。
func sanitizeParams(tool *mcpsec.TableTool, params map[string]any) (map[string]any, error) {
	if tool == nil {
		return nil, fmt.Errorf("mcpguard: 工具不存在")
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	for name, c := range tool.Schema {
		if c == nil || c.Sensitive == "" {
			continue
		}
		v, ok := out[name]
		if !ok {
			continue
		}
		switch c.Sensitive {
		case mcpsec.SensStrip:
			delete(out, name)
		case mcpsec.SensBlock:
			if s, ok := v.(string); ok && s != "" {
				return nil, fmt.Errorf("mcpguard: 字段 %q 含敏感参数被拒绝", name)
			}
		case mcpsec.SensMask:
			if _, ok := v.(string); ok {
				out[name] = "[已脱敏]"
			}
		}
	}
	return out, nil
}

// ParamsHash 对参数规范化后计算 SHA-256，并绑定 tenant_id+req_id 上下文（S-2）。
// 规范化采用 json.Marshal（map 键字典序确定性），保证可比对；只记 hash 不记内容。
func ParamsHash(tenant, reqID string, params map[string]any) string {
	canon, _ := json.Marshal(params)
	h := sha256.Sum256([]byte(tenant + "\x00" + reqID + "\x00" + string(canon)))
	return hex.EncodeToString(h[:])
}