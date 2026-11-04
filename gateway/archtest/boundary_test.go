// boundary_test.go - 四层架构依赖方向门禁（方案 §6.3）
//
// 判据全部来自 AST 的 import 声明，不做字符串子串搜索（注释里提到包名不算依赖——
// 例如 adapters/qwen 的注释会写明"契约由 gateway/route2/orchestrator 定义"）。
package archtest

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// modPath 本仓库 module 路径（go.mod 首行 %module）。刻意写常量而不是解析 go.mod：
// 一旦改名（方案 D4），本文件会连同其它 import 一并被重写，届时同步这行即可。
const modPath = "security-ai-gateway"

// skipDirs 不参与扫描的目录（工具链缓存/文档/历史快照）。
//
// archtest 自身也在表内：国密零命中检查的签名清单本身就写着 "func sm2" 等字面量，
// 不排除会自命中（门禁把自己判红）。
var skipDirs = map[string]bool{
	"vendor":       true,
	"docs":         true,
	".git":         true,
	".tools":       true,
	".gopath-p24":  true,
	".workbuddy":   true,
	"node_modules": true,
	"testdata":     true,
	"archtest":     true,
}

// denyRule 一条"某层不得依赖某层"的规则。
type denyRule struct {
	name   string // 规则名（失败信息首行）
	dir    string // 受约束的目录（含子目录），相对仓库根
	banned string // 禁止出现的模块内 import 前缀
	why    string // 依据（方案条款），便于失败时直接定位
}

// denyRules 方案 §6.3 的四条禁止规则。
//
// 说明：「禁止混合包」一条（同一 package 内不得既有纯计算文件又有 import cryptop 的文件）
// 在本仓落地为**per-file 判定**——即下列规则对每个 .go 文件逐一检查，而不是对包整体。
// 这样比"包内混装"更严：只要有一个文件越界就红，无需再区分"纯计算文件"这种模糊边界。
var denyRules = []denyRule{
	{
		name:   "engine 层不得依赖信任锚：trustedops",
		dir:    "gateway/teecore/trustedops",
		banned: modPath + "/gateway/cryptop",
		why:    "§6.3 ① trustedops 须零 cryptop，才能随新库外发",
	},
	{
		name:   "engine 层不得依赖信任锚：maskedinfer",
		dir:    "gateway/teecore/maskedinfer",
		banned: modPath + "/gateway/cryptop",
		why:    "§6.3 ① maskedinfer 须零 cryptop",
	},
	{
		name:   "engine 层不得依赖信任锚：route2plan",
		dir:    "gateway/teecore/route2plan",
		banned: modPath + "/gateway/cryptop",
		why:    "§6.3 ① route2plan 须零 cryptop",
	},
	{
		name:   "engine 层不得依赖信任锚：route2ref",
		dir:    "gateway/teecore/route2ref",
		banned: modPath + "/gateway/cryptop",
		why:    "§6.3 ① route2ref 须零 cryptop",
	},
	{
		name:   "掩码步引擎不得依赖信任锚：route2step",
		dir:    "gateway/tee-infer-service/route2step",
		banned: modPath + "/gateway/cryptop",
		why:    "§4 步骤5：掩码流由宿主注入（StepContext.NewStream），本包不持密钥实现",
	},
	{
		name:   "适配层不得反向依赖编排层：adapters/*",
		dir:    "gateway/teecore/adapters",
		banned: modPath + "/gateway/route2/orchestrator",
		why:    "§6.3 ② adapters 只实现契约，契约定义方不得反向被依赖（否则拆库时成环）",
	},
	{
		name:   "vLLM 适配器不得依赖宿主包",
		dir:    "gateway/vllm-adapter",
		banned: modPath + "/gateway/tee-infer-service",
		why:    "§8.2④ vllm-adapter 是独立进程，只许依赖明文引擎平面 gateway/modelengine",
	},
	{
		name:   "明文引擎平面不得依赖宿主",
		dir:    "gateway/modelengine",
		banned: modPath + "/gateway/tee-infer-service",
		why:    "§8.2④ 平面包若反向依赖宿主，适配器与宿主就会再次经由它耦合",
	},
	{
		name:   "信任锚不得反向依赖上层：cryptop",
		dir:    "gateway/cryptop",
		banned: modPath + "/gateway/teecore/",
		why:    "§6.3 ④ cryptop 保无环",
	},
	{
		name:   "信任锚不得反向依赖宿主：cryptop",
		dir:    "gateway/cryptop",
		banned: modPath + "/gateway/tee-infer-service/",
		why:    "§6.3 ④ cryptop 保无环",
	},
}

// orchestratorAllowedImporters orchestrator 的合法引用方（替代 internal/ 的封装作用，见 D3）。
//
// 方案 §6.3 ③：只允许网关产品层与 cmd/route2-*。产品层当前落在 gateway/route2/ 下；
// 将来网关主程序若换位置，在此追加一条前缀即可，**不得**为了"图方便"放宽到全仓。
var orchestratorAllowedImporters = []string{
	modPath + "/gateway/route2/",
	modPath + "/cmd/route2-",
}

// TestDependencyDirection 跑全部 deny 规则 + orchestrator 反向引用白名单。
func TestDependencyDirection(t *testing.T) {
	root := repoRoot(t)
	files := collectGoFiles(t, root)

	for _, r := range denyRules {
		r := r
		t.Run(r.dir+" ↛ "+strings.TrimPrefix(r.banned, modPath+"/"), func(t *testing.T) {
			for _, m := range checkDenyRule(r, files) {
				t.Errorf("%s", m)
			}
		})
	}

	t.Run("orchestrator 只允许网关产品层与 cmd/route2-*", func(t *testing.T) {
		target := modPath + "/gateway/route2/orchestrator"
		found := 0
		for _, f := range files {
			if underDir(f.rel, "gateway/route2/orchestrator") {
				continue // 包内自引用不算
			}
			for _, imp := range f.imports {
				if imp != target {
					continue
				}
				found++
				pkg := modPath + "/" + dirOf(f.rel)
				if !hasAnyPrefix(pkg, orchestratorAllowedImporters) {
					t.Errorf("%s:%d\n  违规：%s 引用 %s\n  依据：§6.3 ③ 仅允许网关产品层与 cmd/route2-*（白名单：%v）",
						f.rel, f.line, pkg, target, orchestratorAllowedImporters)
				}
			}
		}
		if found == 0 {
			t.Log("提示：当前无任何包引用 orchestrator（白名单形同空转，属正常早期状态）")
		}
	})
}

// TestNoGuomiImplementation 国密实现零命中门禁（§6.3 首条）。
//
// 本仓只**调用** github.com/emmansun/gmsm，绝不自行实现 SM2/SM3/SM4 原语；
// 该门禁是"整体开源不构成国密实现外发"这一前提的机器证据。
func TestNoGuomiImplementation(t *testing.T) {
	root := repoRoot(t)
	bad := []string{"func SM2", "func SM3", "func SM4", "func sm2", "func sm3", "func sm4"}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || (strings.HasPrefix(d.Name(), "tmp") && p != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		src, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel := relSlash(root, p)
		for i, line := range strings.Split(string(src), "\n") {
			for _, sig := range bad {
				if strings.Contains(line, sig) {
					t.Errorf("%s:%d 疑似国密原语实现：%q（§6.3：国密仅由外部 gmsm 提供）", rel, i+1, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
}

// checkDenyRule 对给定文件集应用单条 deny 规则，返回所有违例信息。
// 正向判据（TestDependencyDirection）与负向对照（TestBoundaryNegativeControl）共用，
// 保证"判定逻辑"与"验证判定逻辑"是同一份代码。
func checkDenyRule(r denyRule, files []srcFile) []string {
	var v []string
	for _, f := range files {
		if !underDir(f.rel, r.dir) {
			continue
		}
		for _, imp := range f.imports {
			if strings.HasPrefix(imp, r.banned) {
				v = append(v, fmt.Sprintf("%s:%d 违规：%s 依赖 %s（%s）", f.rel, f.line, r.dir, imp, r.why))
			}
		}
	}
	return v
}

// orchestratorImporterAllowed 判定某包引用 orchestrator 是否在白名单内（§6.3 ③）。
func orchestratorImporterAllowed(pkg string) bool {
	return hasAnyPrefix(pkg, orchestratorAllowedImporters)
}

// TestBoundaryNegativeControl 负向对照：方案 §6.3 将「门禁必须能做负向对照」列为强制，
// 否则视为「未验证的门禁」。本测试不修改仓库，仅用合成文件集驱动同一份 checkDenyRule /
// orchestratorImporterAllowed，断言：注入违例 → 必红；清理后 → 必绿。
func TestBoundaryNegativeControl(t *testing.T) {
	// 三个代表性 deny 规则：引擎层↛信任锚、适配层↛编排层、vLLM↛宿主。
	reps := []struct {
		ruleIdx  int
		violImp  string // 触发违例的 import
		cleanImp string // 清理后的合法 import
	}{
		{0, modPath + "/gateway/cryptop", modPath + "/gateway/maskedinfer"},
		{5, modPath + "/gateway/route2/orchestrator", modPath + "/gateway/maskedinfer"},
		{6, modPath + "/gateway/tee-infer-service", modPath + "/gateway/modelengine"},
	}
	for _, rep := range reps {
		r := denyRules[rep.ruleIdx]
		viol := []srcFile{{rel: r.dir + "/negctrl_fixture.go", imports: []string{rep.violImp}, line: 1}}
		clean := []srcFile{{rel: r.dir + "/negctrl_fixture.go", imports: []string{rep.cleanImp}, line: 1}}
		if got := checkDenyRule(r, viol); len(got) == 0 {
			t.Errorf("负向对照失败[%s]：构造的违例未被门禁捕获（门禁形同虚设）", r.name)
		}
		if got := checkDenyRule(r, clean); len(got) != 0 {
			t.Errorf("负向对照失败[%s]：清理后门禁仍报红：%v", r.name, got)
		}
	}

	// orchestrator 白名单：非白名单引用方必须被拒，白名单内必须放行。
	outside := modPath + "/gateway/tee-infer-service"
	inside := modPath + "/cmd/route2-qwen"
	if orchestratorImporterAllowed(outside) {
		t.Errorf("负向对照失败：白名单错误放行了 %s", outside)
	}
	if !orchestratorImporterAllowed(inside) {
		t.Errorf("负向对照失败：白名单错误拦截了 %s", inside)
	}
}

// ---- 基础设施 ----

type srcFile struct {
	rel     string // 相对仓库根，斜杠分隔
	imports []string
	line    int // 首条 import 所在行（仅用于报错定位）
}

// repoRoot 从当前目录向上找 go.mod（go test 的工作目录是包目录）。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("未找到 go.mod：archtest 必须在仓库内运行")
		}
		dir = parent
	}
}

// collectGoFiles 解析全仓 .go 文件的 import 声明（含 _test.go：测试也不得越界）。
func collectGoFiles(t *testing.T, root string) []srcFile {
	t.Helper()
	var out []srcFile
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if skipDirs[name] {
				return filepath.SkipDir
			}
			if p != root && strings.HasPrefix(name, "tmp") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if perr != nil {
			return nil // 语法错误交给 go vet/编译器报，本门禁不重复报
		}
		sf := srcFile{rel: relSlash(root, p)}
		for _, spec := range f.Imports {
			path, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				continue
			}
			if sf.line == 0 {
				sf.line = fset.Position(spec.Pos()).Line
			}
			sf.imports = append(sf.imports, path)
		}
		if len(sf.imports) > 0 {
			out = append(out, sf)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历仓库失败: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}

func relSlash(root, p string) string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(r)
}

func dirOf(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return ""
}

func underDir(rel, dir string) bool {
	return rel == dir || strings.HasPrefix(rel, dir+"/")
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
