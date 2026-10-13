-- P1-7 T2c（D-18）：Higress 访问日志 → `/audit/report` 记录映射与租户三层解析。
--
-- 职责（单一）：
--   1) 筛选数据面拒绝（401/403/429）并映射为 result 白名单取值；
--   2) 按 X-Mse-Consumer（key-auth 注入）解析租户；缺失/未命中 → 哨兵租户；
--   3) 整形为 /audit/report 的 auditReportItem 字段。
--
-- ⚠️ 职责边界：本脚本**不计算 HMAC 签名**（X-Audit-Report-Sig）。
--    原因见 audit-report-pipeline.yaml 中的「签名缺口」说明——Fluent Bit 在输出阶段
--    重新序列化载荷，过滤器无法对最终 body 逐字节签名。
--
-- 明令禁止：读取客户端自报 X-Tenant-ID（D-18；被拒请求在 otpmask 前短路 ⇒ 自报值/不存在）。

local MAP_PATH = "/fluent-bit/scripts/consumer-tenant.json"
local SENTINEL = "_unauthenticated"

local consumer_map = nil

local function load_map()
  consumer_map = {}
  local f = io.open(MAP_PATH, "r")
  if not f then
    return
  end
  local raw = f:read("*a")
  f:close()
  -- 极简 JSON 对象解析（形如 {"a":"b","c":"d"}）；映射表键值均为简单字符串。
  for k, v in string.gmatch(raw, '"([^"]+)"%s*:%s*"([^"]*)"') do
    consumer_map[k] = v
  end
end

-- response_code → /audit/report result 白名单（§7.3 item 5）。
local function map_result(code)
  code = tostring(code or "")
  if code == "429" then return "rate_limited" end
  if code == "401" then return "auth_failed" end
  if code == "403" then return "ip_blocked" end
  return nil
end

-- 租户三层解析（D-18）：X-Mse-Consumer → 映射表 → tenant_id；缺失 → 哨兵。
local function resolve_tenant(consumer)
  if consumer ~= nil and consumer ~= "" then
    if consumer_map == nil then load_map() end
    local t = consumer_map[consumer]
    if t ~= nil and t ~= "" then
      return t, "consumer_map"
    end
  end
  return SENTINEL, "unauthenticated"
end

function replay_filter(tag, timestamp, record)
  local result = map_result(record["response_code"])
  if result == nil then
    return 2 -- 非拒绝类，丢弃（本管道只回灌数据面拒绝）
  end

  local tenant, resolution = resolve_tenant(record["x_mse_consumer"])

  local item = {
    request_id = record["request_id"] or "",
    tenant_id = tenant,
    path = record["path"] or "",
    path_mode = "plain",
    http_status = tonumber(record["response_code"]) or 0,
    result = result,
    timestamp_ns = (tonumber(record["date"]) or 0) * 1000000000, -- Fluent Bit date 为秒
    dur_ms = tonumber(record["duration"]) or 0,
    tenant_id_resolution = resolution, -- 证据字段（D-18；服务端据此复核解析来源）
  }

  -- 以单条记录形式交给输出；批量聚合由 Fluent Bit 缓冲/批次完成。
  record["audit_report_item"] = item
  return 1, timestamp, record
end
