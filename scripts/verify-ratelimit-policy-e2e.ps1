# verify-ratelimit-policy-e2e.ps1 - 控制面限流策略实链验证（Phase 1 门禁 #7 / S4）
#
# 覆盖设计 v1.1 §8 判据 3（编译产物下发后 RPM 生效，同窗口对照）与判据 8（回归）：
#   P1 前置：gateway-core / 数据面容器 / Redis 容器
#   P2 Redis registry：本地 standalone 用 **static + 容器 IP**（部署清单用 dns + K8s FQDN，
#      见 deploy/higress/mcp-bridge-registries.yaml 注释）→ 按需补齐 registry
#   A1 策略源写入：PUT /ratelimits（校验→防回滚→签名→落库）并取回 data_plane_config
#   A2 编译产物落地：cluster-key-rate-limit 插件（不存在则创建，存在则按快照回滚语义改写）
#   V1 同窗口对照：tenant=t-a 连续请求出现 429；tenant=t-b 全 200
#   V2 回归：限流仅表现为 200/429（无 5xx）
#   R1 复原：若为本次创建 → 删除插件；若为改写 → 快照回写
#   R2 复原复验：删除/重启后确认限流确实消失（-KeepPolicy 时跳过）
#
# 环境事实（standalone fake-apiserver，2026-09-13 实测）：CR 变更只对 Envoy 推 MODIFIED，
#   新增（ADDED）与删除（REMOVED）**都不下发** → 新建插件后、以及复原删除后，都需重启
#   数据面容器才在数据面生效（本脚本自动处理，故单次运行含至多 2 次 docker restart）。
#   重启后 otpmask 需与 tee-infer 重建握手，首批 503 属设计内 fail-closed → 用 t-b 预热到 200。
#
# 探针路由（-ProbeIngress / -ProbePath）：必须落在插件 matchRules 覆盖的 ingress 上，
#   否则"没生效"与"生效但没触发"无法区分。standalone 环境 `/v1/infer` 的 ingress 名是
#   **otpmask-tee-infer**（生产 deploy 清单里对应 `infer`，见 ingress-infer.yaml），
#   上游是本地 tee-infer，稳定 200（不走外网）。
#
# 未覆盖（如实标注，非本脚本能力范围）：
#   判据 4 影子模式：数据面无影子执行器（插件无该能力）→ 不下发，待后续工作包
#   判据 5 拉取失败保留旧表：插件侧尚未消费 /ratelimits（当前为脚本 apply）→ 仅有单测覆盖
#   判据 7 策略变更审计/回滚：控制面策略变更审计尚未实现 → 待补
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\verify-ratelimit-policy-e2e.ps1 `
#     -Core http://127.0.0.1:8085 -CoreToken <OTP_CORE_AUTH_TOKEN> -Gateway http://127.0.0.1:8080 `
#     -Container higress-chain-control-plane -RedisContainer redis-rate-limit -Rpm 6 -Requests 12
# 退出码：0 = 通过；1 = 存在 FAIL；2 = 脚本自身错误
#
# 注：本脚本为 UTF-8 with BOM（含中文；PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$Core = 'http://127.0.0.1:8085',
    [string]$CoreToken = '',
    [string]$Gateway = 'http://127.0.0.1:8080',
    [string]$Container = 'higress-chain-control-plane',
    [string]$RedisContainer = 'redis-rate-limit',
    [string]$TenantA = 't-a',
    [string]$TenantB = 't-b',
    [string]$ProbeIngress = 'otpmask-tee-infer',
    [string]$ProbePath = '/v1/infer',
    [int]$Rpm = 6,
    [int]$Requests = 12,
    [switch]$KeepPolicy
)

$ErrorActionPreference = 'Stop'
$results = New-Object System.Collections.ArrayList
function Record([string]$id, [string]$title, [bool]$ok, [string]$detail) {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = $tag; Detail = $detail })
    Write-Host ("[{0}] {1} - {2}" -f $tag, $id, $title) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if ($detail) { Write-Host ("        " + $detail) -ForegroundColor DarkGray }
}

function Get-Http([string]$url, [string[]]$headers, [string]$method = 'GET', [string]$body = '') {
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = $method
        $req.Timeout = 20000
        foreach ($h in $headers) { $k, $v = $h -split ':', 2; $req.Headers.Add($k.Trim(), $v.Trim()) }
        if ($body) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
            $req.ContentType = 'application/json'
            $req.ContentLength = $bytes.Length
            $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
        }
        $resp = $req.GetResponse()
        $rd = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $t = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
        return @{ code = [int]$resp.StatusCode; body = $t }
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) {
            $rd = New-Object System.IO.StreamReader($r.GetResponseStream(), [System.Text.Encoding]::UTF8)
            $t = $rd.ReadToEnd(); $rd.Close()
            return @{ code = [int]$r.StatusCode; body = $t }
        }
        return @{ code = -1; body = $_.Exception.Message }
    }
}

# Invoke-InferProbe 发一次探针请求（otpmask 插件负责段① 加密），返回状态码。
function Invoke-InferProbe([string]$tenant) {
    $body = '{"model":"mock","engine_type":"cmaas","messages":[{"role":"user","content":"ratelimit probe"}]}'
    $tmp = Join-Path $env:TEMP 'rl-probe.json'
    [System.IO.File]::WriteAllText($tmp, $body, (New-Object System.Text.UTF8Encoding($false)))
    $curlArgs = @('-s', '-o', 'NUL', '-m', '60', '-w', '%{http_code}', '-X', 'POST', "$Gateway$ProbePath",
        '-H', 'Content-Type: application/json', '-H', "X-Tenant-Id: $tenant", '--data-binary', "@$tmp")
    return (& curl.exe @curlArgs 2>$null).ToString().Trim()
}

# 容器内 REST 操作脚本（kubeconfig 在容器 /app/kubeconfig；不用 kubectl）。
$opPy = @'
import base64, json, re, ssl, sys, tempfile, urllib.request, urllib.error
KC = "/app/kubeconfig"
text = open(KC).read()
server = re.search(r'server:\s*(\S+)', text).group(1)
cb = re.search(r'client-certificate-data:\s*(\S+)', text)
kb = re.search(r'client-key-data:\s*(\S+)', text)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
if cb and kb:
    cf = tempfile.NamedTemporaryFile(delete=False); cf.write(base64.b64decode(cb.group(1))); cf.close()
    kf = tempfile.NamedTemporaryFile(delete=False); kf.write(base64.b64decode(kb.group(1))); kf.close()
    ctx.load_cert_chain(cf.name, kf.name)

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(server + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=30, context=ctx) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

WP = "/apis/extensions.higress.io/v1alpha1/namespaces/higress-system/wasmplugins/cluster-key-rate-limit"
MB = "/apis/networking.higress.io/v1/namespaces/higress-system/mcpbridges/default"
NEW = "/tmp/rl-new-config.json"
SNAP = "/tmp/rl-snapshot.json"
FLAG = "/tmp/rl-created.flag"
mode = sys.argv[1]

if mode == "ensure-registry":
    ip = sys.argv[2]
    code, body = req("GET", MB)
    if code != 200:
        print(json.dumps({"ok": False, "err": "GET mcpbridge %d" % code})); raise SystemExit(0)
    mb = json.loads(body)
    regs = (mb.get("spec") or {}).get("registries") or []
    if any(r.get("name") == "redis-ratelimit" for r in regs):
        print(json.dumps({"ok": True, "note": "registry 已存在"})); raise SystemExit(0)
    regs.append({"name": "redis-ratelimit", "domain": ip + ":6379", "port": 6379,
                 "type": "static", "protocol": "TCP"})
    mb.setdefault("spec", {})["registries"] = regs
    c2, _ = req("PUT", MB, mb)
    print(json.dumps({"ok": c2 == 200, "added": ip + ":6379"})); raise SystemExit(0)

if mode == "apply":
    new_cfg = json.load(open(NEW))
    code, body = req("GET", WP)
    if code == 404:
        # 不存在则按已核验 schema 创建（本地 standalone 的 fake-apiserver 不接受 FAIL_CLOSED，
        # 故不写 failStrategy；生产以 deploy/higress/security-plugins.yaml 为准）
        ci, ib = req("GET", "/apis/networking.k8s.io/v1/namespaces/higress-system/ingresses")
        ais = []
        if ci == 200:
            ais = [i["metadata"]["name"] for i in json.loads(ib).get("items", [])
                   if i.get("metadata", {}).get("name", "").startswith("ai-")]
        # 探针 ingress 必须在 matchRules 内，否则无法区分"未生效"与"生效未触发"
        rules = [{"ingress": [sys.argv[2]], "config": new_cfg}]
        if ais:
            rules.append({"ingress": ais, "config": new_cfg})
        spec = {"url": "http://localhost:8002/plugins/cluster-key-rate-limit/2.0.1/plugin.wasm",
                "failStrategy": "FAIL_OPEN", "defaultConfigDisable": True, "matchRules": rules}
        obj = {"apiVersion": "extensions.higress.io/v1alpha1", "kind": "WasmPlugin",
               "metadata": {"name": "cluster-key-rate-limit", "namespace": "higress-system",
                            "annotations": {"higress.io/wasm-plugin-title": "Cluster Key Rate Limit",
                                            "higress.io/wasm-plugin-category": "traffic"}},
               "spec": spec}
        c2, b2 = req("POST", "/apis/extensions.higress.io/v1alpha1/namespaces/higress-system/wasmplugins", obj)
        if c2 in (200, 201):
            open(FLAG, "w").write("1")
        print(json.dumps({"ok": c2 in (200, 201), "created": c2 in (200, 201), "resp": c2, "ingress_count": len(ais)}))
        raise SystemExit(0)
    # 已存在：快照 + 改写所有 matchRule 的限流字段（保留 redis 等部署字段）
    wp = json.loads(body)
    json.dump(wp, open(SNAP, "w"))
    probe = sys.argv[2]
    mrs = (wp.get("spec") or {}).get("matchRules") or []
    for mr in mrs:
        cfg = mr.setdefault("config", {})
        cfg["rule_name"] = new_cfg["rule_name"]
        cfg["rule_items"] = new_cfg["rule_items"]
        cfg["show_limit_quota_header"] = new_cfg["show_limit_quota_header"]
        cfg["rejected_code"] = new_cfg["rejected_code"]
        cfg.pop("global_threshold", None)
    # 探针 ingress 必须在匹配范围内（否则"未生效"会被误判为"未触发"）
    if not any(probe in (mr.get("ingress") or []) for mr in mrs):
        if mrs:
            mrs[0].setdefault("ingress", []).append(probe)
        else:
            wp["spec"]["matchRules"] = [{"ingress": [probe], "config": dict(new_cfg)}]
    c2, _ = req("PUT", WP, wp)
    print(json.dumps({"ok": c2 == 200, "patched": True, "rules": len(wp["spec"]["matchRules"])}))
    raise SystemExit(0)

if mode == "restore":
    import os
    if os.path.exists(FLAG):
        c2, _ = req("DELETE", WP)
        os.remove(FLAG)
        print(json.dumps({"ok": c2 in (200, 202, 204), "deleted": True})); raise SystemExit(0)
    import os as _os
    if _os.path.exists(SNAP):
        c2, _ = req("PUT", WP, json.load(open(SNAP)))
        print(json.dumps({"ok": c2 == 200, "restored": True})); raise SystemExit(0)
    print(json.dumps({"ok": True, "note": "无需复原"})); raise SystemExit(0)
print(json.dumps({"ok": False, "err": "unknown mode"}))
'@

Write-Host '===== 控制面限流策略实链验证（门禁 #7 / S4）=====' -ForegroundColor Cyan

# ---------- P1 前置 ----------
$health = Get-Http "$Core/health" @()
Record 'P1' 'gateway-core 可达' ($health.code -eq 200) "GET $Core/health -> $($health.code)"
$psOut = & docker ps --filter "name=$Container" --format '{{.Names}}' 2>$null
Record 'P2a' "数据面容器在运行（$Container）" ("$psOut".Trim() -eq $Container) "$psOut"
$redisIp = (& docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $RedisContainer 2>$null)
$redisIp = "$redisIp".Trim()
Record 'P2b' "Redis 容器可达（$RedisContainer）" (-not [string]::IsNullOrWhiteSpace($redisIp)) "ip=$redisIp"

# ---------- 容器内脚本投放 ----------
$pyPath = Join-Path $env:TEMP 'apply-ratelimit.py'
[System.IO.File]::WriteAllText($pyPath, $opPy, (New-Object System.Text.UTF8Encoding($false)))
& docker cp $pyPath "$Container`:/tmp/apply-ratelimit.py" | Out-Null

# ---------- P3 Redis registry（static + 容器 IP） ----------
$regOut = & docker exec $Container python3 /tmp/apply-ratelimit.py ensure-registry $redisIp 2>&1
$regOk = $false
try { $regOk = ((($regOut | Select-Object -Last 1) | ConvertFrom-Json).ok) } catch { }
Record 'P3' 'Redis registry 就绪（redis-ratelimit → static 容器 IP）' $regOk "$regOut"

# ---------- A1 策略源写入（版本号动态取当前 +1，避免与历史写入撞 409 同版本） ----------
$cur = Get-Http "$Core/ratelimits" @("Authorization: Bearer $CoreToken")
$curVer = 0
if ($cur.code -eq 200) { try { $curVer = [int](($cur.body | ConvertFrom-Json).version) } catch { } }
$ver = $curVer + 1
$policy = @{
    version   = $ver
    issued_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    rules     = @(
        @{ id = "$TenantA-rate"; kind = 'rate'; scope = 'tenant'; target = $TenantA
           rpm = $Rpm; action = 'reject'; enabled = $true }
    )
} | ConvertTo-Json -Depth 6
$put = Get-Http "$Core/ratelimits" @("Authorization: Bearer $CoreToken") 'PUT' $policy
$compiled = $null
if ($put.code -eq 200) { $compiled = ($put.body | ConvertFrom-Json) }
$okA1 = $compiled -and $compiled.data_plane_compiled
Record 'A1' "策略写入并通过编译（version=$ver, rpm=$Rpm，当前版本 $curVer）" ([bool]$okA1) "PUT /ratelimits -> $($put.code)；notes=$($compiled.notes -join ' / ')"
if (-not $okA1) {
    Write-Host "`n[中止] 策略写入/编译失败，后续判据无法成立（body=$($put.body)）" -ForegroundColor Red
    exit 1
}

# 本地 standalone：registry 为 static → 插件 redis.service_name 须写 redis-ratelimit.static
$compiled.data_plane_config.redis.service_name = 'redis-ratelimit.static'
$expectedQps = [math]::Ceiling($Rpm / 60.0)
$cfgJson = ($compiled.data_plane_config | ConvertTo-Json -Depth 8 -Compress)
$newCfgPath = Join-Path $env:TEMP 'rl-new-config.json'
[System.IO.File]::WriteAllText($newCfgPath, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))
& docker cp $newCfgPath "$Container`:/tmp/rl-new-config.json" | Out-Null

# ---------- A2 编译产物落地 ----------
$applyOut = & docker exec $Container python3 /tmp/apply-ratelimit.py apply $ProbeIngress 2>&1
$applied = $null
try { $applied = ($applyOut | Select-Object -Last 1) | ConvertFrom-Json } catch { }
Record 'A2' "编译产物落地 cluster-key-rate-limit（期望 $expectedQps QPS；matchRules 含 $ProbeIngress）" ([bool]($applied -and $applied.ok)) "$applyOut"

# standalone fake-apiserver 只向 Envoy 推 MODIFIED 事件（不推 ADDED）：新建插件后必须重启
# 数据面容器才能加载；重启后 otpmask 需与 tee-infer 重建握手，首批 503 属设计内 fail-closed，
# 故用 t-b（策略未覆盖该租户）预热到 200 再进入判据。
if ($applied -and $applied.created) {
    Write-Host '  [信息] 插件为本次新建 → 重启数据面容器以加载（fake-apiserver 不推 ADDED 事件）' -ForegroundColor DarkGray
    & docker restart $Container | Out-Null
    Start-Sleep -Seconds 8
    $warm = ''
    for ($i = 0; $i -lt 30; $i++) {
        $warm = Invoke-InferProbe $TenantB
        if ($warm -eq '200') { break }
        Start-Sleep -Seconds 1
    }
    Record 'A2b' '数据面重启后预热（探针路由稳定 200）' ($warm -eq '200') "last=$warm"
}

# ---------- V1 同窗口对照 ----------
Start-Sleep -Seconds 5
$aCodes = @(); for ($i = 1; $i -le $Requests; $i++) { $aCodes += (Invoke-InferProbe $TenantA) }
$bCodes = @(); for ($i = 1; $i -le $Requests; $i++) { $bCodes += (Invoke-InferProbe $TenantB) }
$aLimit = @($aCodes | Where-Object { $_ -eq '429' }).Count
$bLimit = @($bCodes | Where-Object { $_ -eq '429' }).Count
$aOther = @($aCodes | Where-Object { $_ -ne '200' -and $_ -ne '429' }).Count

Record 'V1' "$TenantA 出现限流（429）" ($aLimit -ge 1) ("codes=" + ($aCodes -join ','))
Record 'V2' "$TenantB 全 200（同窗口对照，桶相互独立）" ($bLimit -eq 0) ("codes=" + ($bCodes -join ','))
Record 'V3' '限流仅表现为 200/429（无 5xx/异常码）' ($aOther -eq 0) "其他码计数=$aOther"

# ---------- R1 复原 ----------
if (-not $KeepPolicy) {
    $resOut = & docker exec $Container python3 /tmp/apply-ratelimit.py restore 2>&1
    $restored = $null
    try { $restored = (($resOut | Select-Object -Last 1) | ConvertFrom-Json) } catch { }
    Record 'R1' '插件配置已复原（删除本次创建 / 快照回写）' ([bool]($restored -and $restored.ok)) "$resOut"
    # 与 A2 同理：CR 变更只推 MODIFIED，删除（REMOVED）不会下发到 Envoy → 已加载的限流
    # 配置仍在生效。故删除后重启容器，并复验"限流确实消失"（否则"复原"只是账面上复原）。
    if ($restored -and $restored.deleted) {
        Write-Host '  [信息] 删除同样不会推送到 Envoy → 重启容器后复验限流已消失' -ForegroundColor DarkGray
        & docker restart $Container | Out-Null
        Start-Sleep -Seconds 8
        $warm = ''
        for ($i = 0; $i -lt 30; $i++) {
            $warm = Invoke-InferProbe $TenantB
            if ($warm -eq '200') { break }
            Start-Sleep -Seconds 1
        }
        $after = @(); for ($i = 1; $i -le 5; $i++) { $after += (Invoke-InferProbe $TenantA) }
        $afterLimit = @($after | Where-Object { $_ -eq '429' }).Count
        Record 'R2' "$TenantA 限流随复原消失（复验）" ($afterLimit -eq 0) ("预热=$warm；codes=" + ($after -join ','))
    }
} else {
    Write-Host '[跳过] -KeepPolicy：保留策略与插件配置' -ForegroundColor DarkYellow
}

# ---------- 汇总 ----------
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
Write-Host "PASS=$pass FAIL=$fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host '未覆盖（如实）：判据 4 影子（数据面无该能力）/ 判据 5 插件侧拉取（当前脚本 apply）/ 判据 7 策略变更审计（未实现）' -ForegroundColor DarkYellow
if ($fail -gt 0) { exit 1 }
exit 0
