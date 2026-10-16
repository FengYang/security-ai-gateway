// Package main — N3 · 远程证明状态与度量看板（§4.3.3，V-S4）。
//
// 端点：
//
//	GET /v1/adminext/tenant/attest    本租户远程证明状态看板 DTO（租户会话，§6.12）
//
// 职责：向租户展示 tee-infer / 飞地的远程证明状态、度量比对结果、厂商证明闭环情况。
// 数据取自 `attest-verify`（P1-8 `gateway/attest-verify/` 资产），经内部通道消费其状态；
// 本方案定义**门户侧 DTO 与降级语义**（上游接口以该资产契约为准）。
//
// 强制披露（C-19，S2/S3/S4 硬约束，数据驱动不依赖 UI 文案）：
//   - 厂商证明未闭环（百炼未接入 / Phala 仅事后记录 / 我方验证器 mock 自签）时，看板显著
//     标注「证明未闭环，不构成已具备能力」，**不得显示为绿色已具备**；
//   - `attest-verify` 不可达/超时 → `overall=unknown` 且各 item 同值，强制渲染「未闭环」——
//     不得用缓存旧状态冒充已验证（N3 item 5；此处以 N3 特定契约覆盖 §6.12 通用 503）；
//   - 任一 item `closed_loop=false` 或 `status ∈ {mock_signed, unknown}` → 该组件级
//     禁用「已具备」样式（DTO 暴露 `capable=false`）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// 端点路径与上游状态路径。
const (
	tenantAttestPath   = tenantSessionBase + "/attest"
	attestStatusPath   = "/status" // attest-verify 状态子路径（上游契约，P1-8）
	attestFetchTimeout = 5 * time.Second
	// defaultAttestTimeoutSec 状态拉取超时秒数（env 缺省，供 config 侧引用）。
	defaultAttestTimeoutSec = 5
	// attestMaxBody 上游响应体读取上限（防异常大响应）。
	attestMaxBody = 1 << 20
)

// 证明状态取值（§4.3.3 DTO：verified|unverified|mock_signed|unknown）。
const (
	attestStatusVerified   = "verified"
	attestStatusUnverified = "unverified"
	attestStatusMockSigned = "mock_signed"
	attestStatusUnknown    = "unknown"
)

// C-19 强制披露文案（数据驱动，不由 UI 填写）。
const (
	attestNoteNotClosedLoop = "证明未闭环，不构成已具备能力（C-19）"
	attestNoteUnreachable   = "attest-verify 不可达/超时，证明未闭环（不得以缓存旧状态冒充已验证，C-19）"
)

// attestItem 单组件证明状态（§4.3.3 DTO）。
type attestItem struct {
	Component  string `json:"component"`
	Status     string `json:"status"`
	ClosedLoop bool   `json:"closed_loop"`
	Note       string `json:"note,omitempty"`
	// Capable 已具备能力（C-19 强制：= status==verified && closed_loop；否则禁用绿色已具备样式）。
	Capable bool `json:"capable"`
}

// attestView GET /tenant/attest 响应 DTO（§4.3.3）。
type attestView struct {
	Tenant      string `json:"tenant"`
	GeneratedAt int64  `json:"generated_at"`
	Overall     string `json:"overall"`
	// Capable 整体是否已具备能力（= overall==verified；C-19：未闭环一律 false，不得绿色）。
	Capable bool         `json:"capable"`
	Items   []attestItem `json:"items"`
}

// ---------- 上游状态源（可注入；nil = 未接线 → 降级 unknown）----------

// attestStatusSource 拉取 attest-verify 状态（内部通道）；失败必须返回 error（降级语义）。
type attestStatusSource interface {
	FetchAttestStatus(ctx context.Context) ([]attestItem, error)
}

// httpAttestStatusSource 经 HTTP 消费 attest-verify 状态（回环/内部通道）。
type httpAttestStatusSource struct {
	baseURL string
	token   string
	client  *http.Client
}

// newHTTPAttestStatusSource 构造状态源；baseURL 为空 → nil（未接线 → 降级 unknown）。
func newHTTPAttestStatusSource(baseURL, token string, timeout time.Duration) *httpAttestStatusSource {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = attestFetchTimeout
	}
	return &httpAttestStatusSource{baseURL: baseURL, token: token, client: &http.Client{Timeout: timeout}}
}

// FetchAttestStatus 拉取并解析上游状态；任何非 200/解析失败/不可达 → error（触发降级）。
func (s *httpAttestStatusSource) FetchAttestStatus(ctx context.Context) ([]attestItem, error) {
	if s == nil || s.baseURL == "" {
		return nil, errors.New("attest: 状态源未配置")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+attestStatusPath, nil)
	if err != nil {
		return nil, fmt.Errorf("attest: 构造请求失败: %w", err)
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attest: 调用状态源失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attest: 状态源返回 %d", resp.StatusCode)
	}
	var out struct {
		Items []attestItem `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, attestMaxBody)).Decode(&out); err != nil {
		return nil, fmt.Errorf("attest: 状态解析失败: %w", err)
	}
	return out.Items, nil
}

// ---------- 场景 → 期望组件目录（降级时按此渲染「各 item 同值 unknown」）----------

// attestComponentCatalogue 场景期望组件（S1–S5 差异，§4.3.3）：
// S1 无证明（明文路径）；S2 厂商侧证明 + 我方 cmaas_attest 锚点；S3/S4 我方证明。
func attestComponentCatalogue(scenario string) []string {
	switch scenario {
	case scenarioS1:
		return nil
	case scenarioS2:
		return []string{"vendor_tee", "cmaas_attest"}
	default: // S3a / S3b / S4：我方证明
		return []string{"tee-infer"}
	}
}

// normalizeAttestStatus 归一化未知状态值为 unknown（fail-closed，不得误判为已验证）。
func normalizeAttestStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case attestStatusVerified:
		return attestStatusVerified
	case attestStatusUnverified:
		return attestStatusUnverified
	case attestStatusMockSigned:
		return attestStatusMockSigned
	default:
		return attestStatusUnknown
	}
}

// deriveAttestOverall 由各组件状态推导整体结论（最谨慎优先）：
// 任一 unknown → unknown；任一 mock_signed → mock_signed；任一 unverified 或未闭环 → unverified；
// 全部 verified 且闭环 → verified；无 item（如 S1 无证明）→ unverified。
func deriveAttestOverall(items []attestItem) string {
	if len(items) == 0 {
		return attestStatusUnverified
	}
	hasMock, hasUnverified, hasOpen := false, false, false
	for _, it := range items {
		switch it.Status {
		case attestStatusUnknown:
			return attestStatusUnknown
		case attestStatusMockSigned:
			hasMock = true
		case attestStatusUnverified:
			hasUnverified = true
		}
		if !it.ClosedLoop {
			hasOpen = true
		}
	}
	if hasMock {
		return attestStatusMockSigned
	}
	if hasUnverified || hasOpen {
		return attestStatusUnverified
	}
	return attestStatusVerified
}

// assembleAttestView 组装看板 DTO（纯函数）：降级 + 归一化 + C-19 强制披露。
//   - srcErr != nil：overall=unknown，按场景目录渲染各 item 同值 unknown（强制未闭环）；
//   - 否则：归一化各 item 状态，verified 但未闭环 → capable=false；缺 note 且不可用 → 补披露文案。
func assembleAttestView(scenario, tenantID string, now int64, raw []attestItem, srcErr error) attestView {
	if srcErr != nil {
		cat := attestComponentCatalogue(scenario)
		items := make([]attestItem, 0, len(cat))
		for _, c := range cat {
			items = append(items, attestItem{
				Component: c, Status: attestStatusUnknown, ClosedLoop: false,
				Note: attestNoteUnreachable, Capable: false,
			})
		}
		return attestView{Tenant: tenantID, GeneratedAt: now, Overall: attestStatusUnknown, Capable: false, Items: items}
	}
	items := make([]attestItem, 0, len(raw))
	for _, it := range raw {
		it.Status = normalizeAttestStatus(it.Status)
		it.Capable = it.Status == attestStatusVerified && it.ClosedLoop
		if !it.Capable && it.Note == "" {
			it.Note = attestNoteNotClosedLoop
		}
		items = append(items, it)
	}
	overall := deriveAttestOverall(items)
	return attestView{
		Tenant: tenantID, GeneratedAt: now, Overall: overall,
		Capable: overall == attestStatusVerified, Items: items,
	}
}

// ---------- 端点 ----------

// registerTenantAttestMux 注册证明状态看板端点（租户令牌；只读无需 CSRF）。
func (h *tenantHandler) registerTenantAttestMux(mux *http.ServeMux) {
	mux.HandleFunc("GET "+tenantAttestPath, tenantAuthMiddleware(h.cfg, h.handleTenantAttest))
}

// handleTenantAttest GET /tenant/attest：拉取 attest-verify 状态并返回看板 DTO；
// 不可达/超时 → overall=unknown + 强制未闭环（C-19，N3 item 5；不 503）。
func (h *tenantHandler) handleTenantAttest(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	var raw []attestItem
	var srcErr error
	if h.attest != nil {
		raw, srcErr = h.attest.FetchAttestStatus(r.Context())
	} else {
		srcErr = errors.New("attest-verify 未接线")
	}
	scenario := ""
	if prov, perr := h.store.GetProvisioning(tenantID); perr == nil && prov != nil {
		scenario = prov.Scenario
	}
	if srcErr != nil {
		log.Printf("[tenant-attest] 证明状态不可用 tenant=%s: %v（强制未闭环，C-19）", tenantID, srcErr)
	}
	tenantWriteJSON(w, http.StatusOK, assembleAttestView(scenario, tenantID, time.Now().Unix(), raw, srcErr))
}

// ---------- N10 启动自检（§4.3.10，V-S3）----------

// n10SelfCheckTimeout 启动自检超时（避免阻塞启动序列）。
const n10SelfCheckTimeout = 10 * time.Second

// portalTrustAxis 判定门户轴 A（§3.6.3）：任一已开通租户 trust_tier=untrusted → 需自检。
// 判定所需数据读取失败 → 返回错误（无法判定轴 A 即 fail-closed）。
func portalTrustAxis(store TenantStore) (bool, error) {
	ids, err := store.ListProvisionedTenants()
	if err != nil {
		return false, fmt.Errorf("N10 轴 A 判定失败（枚举开通租户）: %w", err)
	}
	for _, id := range ids {
		p, err := store.GetProvisioning(id)
		if err != nil {
			return false, fmt.Errorf("N10 轴 A 判定失败（读取租户 %s 开通配置）: %w", id, err)
		}
		if p != nil && p.TrustTier == trustTierUntrusted {
			return true, nil
		}
	}
	return false, nil
}

// n10StartupSelfCheck 门户启动自检（N10 item 6，落点 main.go 启动序列）：
//   - 轴 A=trusted（或无已开通租户）→ 跳过自检仅记日志（避免无可信环境时无法启动）；
//   - 轴 A=untrusted → **强制**调用 attest-verify 度量自检；不可达/未接线/度量异常
//     （overall != verified，含 mock 自签与未知）→ fail-closed 拒启动并告警（V-S3）。
func n10StartupSelfCheck(store TenantStore, src attestStatusSource) error {
	untrusted, err := portalTrustAxis(store)
	if err != nil {
		return err
	}
	if !untrusted {
		log.Printf("[n10] 启动自检：轴 A=trusted（无 untrusted 租户），跳过 attest-verify 度量自检")
		return nil
	}
	if src == nil {
		return errors.New("[n10] 轴 A=untrusted 但 attest-verify 未接线（ATTEST_STATUS_URL 未配置），fail-closed 拒启动")
	}
	ctx, cancel := context.WithTimeout(context.Background(), n10SelfCheckTimeout)
	defer cancel()
	items, err := src.FetchAttestStatus(ctx)
	if err != nil {
		return fmt.Errorf("[n10] 轴 A=untrusted，attest-verify 自检不可用，fail-closed 拒启动: %w", err)
	}
	if overall := deriveAttestOverall(items); overall != attestStatusVerified {
		return fmt.Errorf("[n10] 轴 A=untrusted，度量自检异常（overall=%s），fail-closed 拒启动并告警", overall)
	}
	log.Printf("[n10] 启动自检通过：轴 A=untrusted，attest-verify 度量 verified（%d 项）", len(items))
	return nil
}
