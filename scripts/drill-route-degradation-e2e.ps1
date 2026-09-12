# drill-route-degradation-e2e.ps1 - 门禁 #5 决定性 E2E：L2 降级可观测 + 验签拒表
#
# 与 drill-core-degradation.ps1 的分工（后者负责"未启用路由的兼容性"与"fail-closed 不降级"）：
# 本脚本补齐**有区分度**的观测点——用 otpmask_route_degraded_total 作为判据，证明插件真的：
#   §6 第 8 行：坏签名路由表 ⇒ 被拒绝、缓存不写入（降级计数不增长）
#   §6 第 3 行：好签名路由表 ⇒ 入缓存 ⇒ 后续请求命中 L2 ⇒ 降级计数增长
#
# 做法：新增临时 Service/Endpoints（gateway-core → 宿主 192.168.65.254:18085，与 tee-infer
# 同法接入）+ 宿主 stub（scripts/stub-gateway-core.ps1 出签名表）+ 临时启用插件路由配置。
# 结束（含失败路径）一定清理：杀 stub、删临时 yaml、还原 CR、重启容器。
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts\drill-route-degradation-e2e.ps1
# 退出码：0 = 全部 PASS；1 = 有 FAIL；2 = 脚本错误
# 注：UTF-8 with BOM。

param(
    [string]$Gateway = 'http://127.0.0.1:8080',
    [string]$Container = 'higress-chain-control-plane',
    [int]$StubPort = 18085,
    [string]$HostIp = '192.168.65.254',
    [string]$RouteKeyHex = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    # 诊断取证：dump 插件 VM 配置 / Envoy 集群 / stub 请求计数，用于区分"配置未到达插件"
    # 与"集群创建失败被静默吞掉"这两类根因。
    [switch]$Diagnose
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$crFile = Join-Path $repo 'higress-standalone\wasmplugins\otpmask-1.0.0.yaml'
$svcFile = Join-Path $repo 'higress-standalone\services\gateway-core.yaml'
$epFile = Join-Path $repo 'higress-standalone\endpoints\gateway-core.yaml'
$stubScript = Join-Path $PSScriptRoot 'stub-gateway-core.ps1'
$tmp = $env:TEMP
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$results = New-Object System.Collections.ArrayList
$stubProc = $null

function Record([string]$id, [string]$title, [string]$status, [string]$detail) {
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = $status; Detail = $detail })
    Write-Output ("[{0}] {1} - {2}" -f $status, $id, $title)
    if ($detail) { Write-Output ("        " + $detail) }
}

function Get-EnvoyStat([string]$name) {
    $out = docker exec $Container curl -s http://127.0.0.1:15000/stats 2>$null
    $line = $out | Select-String -Pattern ("wasmcustom\." + [regex]::Escape($name) + ":") | Select-Object -First 1
    if (-not $line) { return -1 }
    return [int](($line.ToString() -split ':')[-1].Trim())
}

function Invoke-InferProbe {
    $bodyFile = Join-Path $tmp 'drill-e2e-infer.json'
    [System.IO.File]::WriteAllText($bodyFile, '{"text":"drill-e2e-probe"}', $utf8NoBom)
    $outFile = Join-Path $tmp 'drill-e2e-infer.out'
    if (Test-Path $outFile) { Remove-Item $outFile -Force }
    # 关键：L2 查询键 = (X-Tenant-ID, X-Otp-Model 或 config.Model)。探针必须携带与 stub
    # 路由表一致的维度，否则 Lookup 必然 miss（2026-09-12 实测：不带这两个头时插件查的是
    # ("", "mock")，与 stub 的 ("tenant-a","qwen-plus") 不匹配 → 降级永不发生）。
    # 注意 header 值不含空格（PS 向原生命令传参的拆分坑）。
    $code = & curl.exe -s -m 30 -o $outFile -w '%{http_code}' -X POST "$Gateway/v1/infer" -H X-Tenant-ID:tenant-a -H X-Otp-Model:qwen-plus --data-binary "@$bodyFile"
    $parsed = 0
    if ($code) { [void][int]::TryParse(($code | Select-Object -Last 1).ToString().Trim(), [ref]$parsed) }
    return $parsed
}

function Wait-ContainerReady([int]$TimeoutSec = 150) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        try {
            $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8080/' -UseBasicParsing -TimeoutSec 5
            if ($r.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Seconds 3
    }
    return $false
}

function Restart-Container {
    docker stop $Container | Out-Null
    docker start $Container | Out-Null
    $ok = Wait-ContainerReady
    $jar = '/tmp/fork-console-usage.jar'
    $has = docker exec $Container sh -c 'test -f /tmp/fork-console-usage.jar && echo yes' 2>$null
    if ($has -match 'yes') {
        docker exec -d -e HIGRESS_CONSOLE_KUBE_CONFIG=/app/kubeconfig -e SERVER_PORT=18001 `
            -e ADMIN_SVC_TARGET=http://host.docker.internal:19095 `
            -e ADMIN_SVC_JWT_SECRET=admin-smoke-shared-secret-2026 $Container java -jar $jar
    }
    return $ok
}

function Start-Stub([bool]$Bad) {
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stubScript, '-Port', "$StubPort", '-KeyHex', $RouteKeyHex)
    if ($Bad) { $argv += '-BadSignature' }
    $log = Join-Path $tmp ('stub-gwcore-' + $(if ($Bad) { 'bad' } else { 'good' }) + '.log')
    return Start-Process powershell -ArgumentList $argv -WindowStyle Hidden -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err"
}

function Stop-Stub {
    if ($stubProc -and -not $stubProc.HasExited) { Stop-Process -Id $stubProc.Id -Force -ErrorAction SilentlyContinue }
}

$backup = "$crFile.e2ebak"
try {
    # ---- 0. 前置 ----
    foreach ($f in @($crFile, $stubScript)) {
        if (-not (Test-Path $f)) { Record 'P0' '前置文件存在' 'FAIL' ("缺 " + $f); throw 'missing prerequisite' }
    }

    # ---- 1. 临时 Service/Endpoints（宿主 stub 接入）----
    $svc = @"
apiVersion: v1
kind: Service
metadata:
  labels:
    higress: higress-system-gateway-core
  name: gateway-core
  namespace: higress-system
spec:
  clusterIP: None
  ports:
    - name: http
      port: $StubPort
      protocol: TCP
      targetPort: $StubPort
  selector:
    app: gateway-core
  type: ClusterIP
"@
    $ep = @"
apiVersion: v1
kind: Endpoints
metadata:
  name: gateway-core
  namespace: higress-system
subsets:
  - addresses:
      - ip: $HostIp
    ports:
      - name: http
        port: $StubPort
"@
    [System.IO.File]::WriteAllText($svcFile, $svc, $utf8NoBom)
    [System.IO.File]::WriteAllText($epFile, $ep, $utf8NoBom)
    # 关键：仅 Service+Endpoints 不足以让控制器物化**出站集群**——tee-infer 是靠 Ingress
    # （higress.io/destination: tee-infer:19090）才物化出 outbound 集群的（2026-09-12 取证：
    # 无 Ingress 时 clusters 里查不到 gateway-core，插件拉取静默失败、stub 零请求）。
    $ingFile = Join-Path $repo 'higress-standalone\ingresses\drill-gateway-core.yaml'
    $ing = @"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  labels:
    higress.io/domain_higress-default-domain: "true"
    higress.io/resource-definer: higress
  name: drill-gateway-core
  namespace: higress-system
  annotations:
    higress.io/destination: gateway-core:$StubPort
spec:
  ingressClassName: higress
  rules:
    - http:
        paths:
          - backend:
              service:
                name: gateway-core
                port:
                  number: $StubPort
            path: /routes
            pathType: Prefix
"@
    [System.IO.File]::WriteAllText($ingFile, $ing, $utf8NoBom)
    Write-Output ("已创建临时 Service/Endpoints/Ingress -> " + $HostIp + ":" + $StubPort)

    # ---- 2. 坏签名阶段：起 stub(bad) + 启用路由 + 重启 ----
    $stubProc = Start-Stub $true
    Start-Sleep -Seconds 2
    Copy-Item $crFile $backup -Force
    $yaml = Get-Content $crFile -Raw -Encoding UTF8
    $inject = @"
      gateway_core_enabled: true
      gateway_core_service: gateway-core.higress-system.svc.cluster.local
      gateway_core_port: $StubPort
      route_verify_key: $RouteKeyHex
      max_stale_seconds: 300
"@
    $repl = '${1}require_auth: false' + "`n" + $inject.TrimEnd()
    $yaml2 = $yaml -replace '(?m)^(\s*)require_auth: false\s*$', $repl
    if ($yaml2 -eq $yaml) { Record 'P1' 'CR 注入路由配置' 'FAIL' '未找到 require_auth 锚点'; throw 'inject anchor missing' }
    [System.IO.File]::WriteAllText($crFile, $yaml2, $utf8NoBom)

    if (-not (Restart-Container)) { Record 'P1' '容器重启就绪' 'FAIL' '超时' }

    $d0 = Get-EnvoyStat 'otpmask_route_degraded_total'
    $codes = @()
    for ($i = 1; $i -le 3; $i++) { $codes += (Invoke-InferProbe); Start-Sleep -Seconds 3 }
    $d1 = Get-EnvoyStat 'otpmask_route_degraded_total'
    Write-Output ("坏签名阶段：探针 HTTP=" + ($codes -join ',') + "，route_degraded " + $d0 + " -> " + $d1 + "（-1 表示指标未注册）")
    if ($d1 -le $d0) {
        Record 'P2E-4' '§6 第 8 行：坏签名路由表被拒绝、缓存不写入（降级计数不增长）' 'PASS' ("route_degraded " + $d0 + " -> " + $d1)
    } else {
        Record 'P2E-4' '§6 第 8 行：坏签名路由表被拒绝、缓存不写入（降级计数不增长）' 'FAIL' ("route_degraded " + $d0 + " -> " + $d1)
    }

    # ---- 3. 好签名阶段：换 stub(good) + 再次探针 ----
    Stop-Stub
    $stubProc = Start-Stub $false
    Start-Sleep -Seconds 2
    $d2 = Get-EnvoyStat 'otpmask_route_degraded_total'
    $codes2 = @()
    for ($i = 1; $i -le 4; $i++) { $codes2 += (Invoke-InferProbe); Start-Sleep -Seconds 4 }
    $d3 = Get-EnvoyStat 'otpmask_route_degraded_total'
    Write-Output ("好签名阶段：探针 HTTP=" + ($codes2 -join ',') + "，route_degraded " + $d2 + " -> " + $d3)
    if ($d3 -gt $d2) {
        Record 'P2E-3' '§6 第 3 行：好签名路由表入缓存 ⇒ 命中 L2 ⇒ 降级事件可观测' 'PASS' ("route_degraded " + $d2 + " -> " + $d3 + "（探针 HTTP=" + ($codes2 -join ',') + "）")
    } else {
        Record 'P2E-3' '§6 第 3 行：好签名路由表入缓存 ⇒ 命中 L2 ⇒ 降级事件可观测' 'FAIL' ("route_degraded 未增长（" + $d2 + " -> " + $d3 + "）；可能原因：容器→宿主 stub 不可达 / 拉取未触发")
    }
    # ---- 2b. 诊断取证（-Diagnose）----
    if ($Diagnose) {
        Write-Output '----- 诊断取证 -----'
        $cd = docker exec $Container curl -s http://127.0.0.1:15000/config_dump 2>$null
        $cdHit = $cd | Select-String 'gateway_core_enabled|route_verify_key|max_stale_seconds'
        if (@($cdHit).Count -gt 0) {
            Record 'P2E-D1' '路由配置是否到达插件 VM（排除配置未送达）' 'PASS' ("config_dump 命中 " + @($cdHit).Count + " 行")
        } else {
            Record 'P2E-D1' '路由配置是否到达插件 VM（排除配置未送达）' 'FAIL' 'config_dump 无路由键 → 配置未到达插件（routeEnabled()=false，拉取不会被调用）'
        }
        $cl = docker exec $Container curl -s http://127.0.0.1:15000/clusters 2>$null
        $clHit = $cl | Select-String 'gateway-core|18085'
        if (@($clHit).Count -gt 0) {
            Record 'P2E-D2' 'Envoy 是否物化 gateway-core 集群（排除集群创建失败）' 'PASS' ("clusters 命中 " + @($clHit).Count + " 行")
        } else {
            Record 'P2E-D2' 'Envoy 是否物化 gateway-core 集群（排除集群创建失败）' 'FAIL' 'clusters 无 gateway-core/18085 → FQDNCluster 未建立（拉取无法发出）'
        }
        foreach ($tag in @('bad', 'good')) {
            $lf = Join-Path $tmp ("stub-gwcore-" + $tag + ".log")
            if (Test-Path $lf) {
                $reqs = Get-Content $lf | Select-String '<-'
                Write-Output ("  stub(" + $tag + ") 收到请求数 = " + @($reqs).Count)
            }
        }
        # 拉取链路计数：cb 恒为 -1（未注册）⇒ 回调从未执行（异步回调被丢弃）；
        # cb 增长但 ok 不增长 ⇒ 回调执行了但表被拒（验签/版本）；ok 增长但 degraded 不动 ⇒ 查询键仍不匹配。
        foreach ($c in @('otpmask_route_fetch_cb_total', 'otpmask_route_fetch_ok_total', 'otpmask_route_fetch_reject_total')) {
            Write-Output ("  " + $c + " = " + (Get-EnvoyStat $c) + "（-1 = 未注册）")
        }
    }
} finally {
    # ---- 4. 清理（无论成败）----
    Stop-Stub
    if (Test-Path $backup) { Copy-Item $backup $crFile -Force; Remove-Item $backup -Force }
    $ingFileCleanup = Join-Path $repo 'higress-standalone\ingresses\drill-gateway-core.yaml'
    foreach ($f in @($svcFile, $epFile, $ingFileCleanup)) { if (Test-Path $f) { Remove-Item $f -Force } }
    $ready = Restart-Container
    Record 'P9' '清理：杀 stub、删临时 yaml、还原 CR、重启容器' $(if ($ready) { 'PASS' } else { 'FAIL' }) '已还原 baseline'
}

Write-Output ''
Write-Output '===== 验收矩阵（§6 降级阶梯 · E2E 决定性项）====='
$results | Format-Table -AutoSize | Out-String | Write-Output
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Output ("汇总：PASS=" + @($results | Where-Object { $_.Status -eq 'PASS' }).Count + " FAIL=" + $fail)
if ($fail -gt 0) { exit 1 }
exit 0
