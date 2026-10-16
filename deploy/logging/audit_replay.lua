-- P1-7 T2c（D-18/D-20）：Higress 访问日志 → 回灌管道的**筛选器**（Fluent Bit Lua）。
--
-- 职责（收敛后，2026-10-14 联调修正）：**只做筛选**，保留原记录字段不变。
--   · 仅放行数据面拒绝（401 / 403 / 429）；其余返回 2 丢弃；
--   · 不做 result 映射、不做租户解析、不改字段——这些下沉到**极薄签名器**
--     （cmd/audit-sign-relay 的 transform），原因见文件末尾「职责为何下沉」。
--
-- 明令禁止：读取客户端自报 X-Tenant-ID（D-18；被拒请求在 otpmask 前短路 ⇒ 自报值/不存在）。

-- 数据面拒绝状态码集合（§7.3 item 5 回灌映射的三类）。
local REPLAY_CODES = { ["401"] = true, ["403"] = true, ["429"] = true }

function replay_filter(tag, timestamp, record)
  local code = tostring(record["response_code"] or "")
  if not REPLAY_CODES[code] then
    -- ⚠️ 丢弃必须用 **-1 且只返回这一个值**（2026-10-14 联调修正）：
    --    Fluent Bit 的 lua filter 对返回码 2 期望「(code, timestamp, record)」三元组，
    --    只返回单个 2 会让栈顶不是 table ⇒ 报 "invalid table returned"。
    return -1
  end
  -- 保留：返回 **同一张表** + 原时间戳（code=2：已修改但时间戳不变）。
  record["audit_replay"] = "1"
  return 2, timestamp, record
end

-- ─────────────────────────────────────────────────────────────────────────────
-- 【职责为何下沉】2026-10-14 联调实测：
--   1) 原实现把 item 嵌套为 record["audit_report_item"] → http output 发送
--      「原访问日志 + 嵌套字段」，不符合 /audit/report 契约 ⇒ 整批 400；
--   2) 改为直接返回新表 item → Fluent Bit 报 "invalid table returned"
--      （该过滤器要求返回传入的同一张表，不支持替换）；
--   3) 改为「清空 record 后重填」仍报同错 ⇒ 该约束无法在 Lua 侧绕过。
--   ⇒ 故 Lua 只保留筛选，整形/映射/租户解析由签名器用 Go 实现（有单测保障），
--      且只取白名单字段（不把 ai_log 等可能含明文的字段带进上报链路）。
-- ─────────────────────────────────────────────────────────────────────────────
