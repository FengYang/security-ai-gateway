package api

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
)

// 本文件实现门禁 #7 / S2 的限流表下发接口（设计 v1.1 §4）：
//   GET /ratelimits  拉路径数据源（与 /routes 同构：始终返回完整签名表）
//   PUT /ratelimits  策略源写入（严格解码 → 校验 → 防回滚 → 签名 → 落库 → 返回编译产物）
//
// 请求体上限由 main.go 的 limitBody 中间件统一约束（4MiB），此处不再重复限制。

// handleGetRateLimits 返回当前限流表（含签名）；未配置时返回空表占位。
func (s *Server) handleGetRateLimits(w http.ResponseWriter, r *http.Request) {
	tbl := s.store.GetRateLimitTable()
	if tbl == nil {
		tbl = ratelimit.NewTable(0, time.Unix(0, 0)) // 空表占位：插件侧验签不过 → 保留旧表（不限流）
	}
	writeJSON(w, http.StatusOK, tbl)
}

// handlePutRateLimits 接收未签名的策略表：校验通过后由控制面签名并落库。
//
// 返回体附带**数据面编译产物**（cluster-key-rate-limit 配置）与 Note 列表，
// 便于运维确认"下发即生效形态"（编译失败不影响策略表落库，但不下发数据面配置）。
func (s *Server) handlePutRateLimits(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	tbl, err := ratelimit.DecodeTable(body)
	if err != nil {
		// 未知字段（如认证类配置）在此被拒：策略通道不得作为高权通道
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	if err := tbl.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}

	cur := s.store.GetRateLimitTable()
	curVer := 0
	if cur != nil {
		curVer = cur.Version
	}
	switch ratelimit.CheckVersion(curVer, tbl.Version) {
	case ratelimit.VersionStale:
		writeError(w, http.StatusConflict, "version_stale",
			fmt.Sprintf("版本 %d 低于当前 %d，拒绝下发（防回滚）", tbl.Version, curVer))
		return
	case ratelimit.VersionSame:
		writeError(w, http.StatusConflict, "version_same",
			fmt.Sprintf("版本 %d 与当前相同，拒绝下发（变更须递增版本，避免同版本内容漂移）", tbl.Version))
		return
	}

	if err := s.rlsigner.SignTable(tbl); err != nil {
		writeError(w, http.StatusInternalServerError, "sign_failed", "策略表签名失败")
		return
	}
	s.store.SaveRateLimitTable(tbl)

	resp := map[string]any{
		"version": tbl.Version,
		"rules":   len(tbl.Rules),
	}
	cfg, notes, cerr := ratelimit.CompileDataPlane(tbl, ratelimit.DefaultCompileOptions())
	resp["notes"] = notes
	if cerr != nil {
		// 与设计 §6 一致：编译失败不下发数据面配置（保留现状），此处如实回报
		resp["data_plane_compiled"] = false
		resp["data_plane_error"] = cerr.Error()
	} else {
		resp["data_plane_compiled"] = true
		resp["data_plane_config"] = cfg
	}
	writeJSON(w, http.StatusOK, resp)
}
