package mcpguard

import (
	"fmt"
	"regexp"

	"security-ai-gateway/gateway/mcpsec"
)

// ValidateSchema 对工具参数做 schema 强校验（FR2，JSON Schema 子集）。
// 校验规则：required 必须存在；type 匹配（string/number/boolean）；
// string 支持 pattern（Go 正则）与 whitelist；命中任一不符即返回错误（拒绝投递）。
func ValidateSchema(tool *mcpsec.TableTool, params map[string]any) error {
	if tool == nil {
		return fmt.Errorf("mcpguard: 工具不存在")
	}
	for _, req := range tool.Required {
		if _, ok := params[req]; !ok {
			return fmt.Errorf("mcpguard: 缺少必填参数 %q", req)
		}
	}
	for name, c := range tool.Schema {
		if c == nil {
			continue
		}
		if name == "" {
			return fmt.Errorf("mcpguard: schema 含空字段名")
		}
		if v, ok := params[name]; ok { // 可选参数缺省不校验
			if err := checkField(c, name, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkField(c *mcpsec.FieldConstraint, name string, v any) error {
	switch c.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("mcpguard: 字段 %q 期望 string", name)
		}
		if c.Pattern != "" {
			re, err := regexp.Compile(c.Pattern)
			if err != nil {
				return fmt.Errorf("mcpguard: 字段 %q 的 pattern 非法", name)
			}
			if !re.MatchString(s) {
				return fmt.Errorf("mcpguard: 字段 %q 不满足 pattern", name)
			}
		}
		if len(c.Whitelist) > 0 && !stringIn(s, c.Whitelist) {
			return fmt.Errorf("mcpguard: 字段 %q 不在白名单", name)
		}
	case "number":
		switch v.(type) {
		case float64, int, int64:
		default:
			return fmt.Errorf("mcpguard: 字段 %q 期望 number", name)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("mcpguard: 字段 %q 期望 boolean", name)
		}
	default:
		return fmt.Errorf("mcpguard: 字段 %q 含未知 type %q", name, c.Type)
	}
	return nil
}

func stringIn(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}