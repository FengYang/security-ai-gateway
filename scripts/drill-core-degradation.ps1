# drill-core-degradation.ps1 - Phase 2 门禁 #5「core 故障降级演练」
#
# 依据：《GA-Gateway-Core-推拉结合设计.md》§6「降级与 fail-closed 语义（一次性定稿）」。
# 目标：把 §6 阶梯在**真实链路**上逐条验证并留证据，而不是只看单测。
#
# 分阶段（默认只跑安全阶段）：
#   P1（只读）：当前配置（路由未启用）→ 请求仍 fail-closed、且不出现降级指标
#              → 证明"接线未启用 = 行为与接线前一致"（§6 兼容性前提）
#   P2（需 -EnableRouting，会**临时改 WasmPlugin CR 并重启容器**）：
#              注入 gateway_core_enabled + route_verify_key + max_stale_seconds
#              → 断言：无处方 + 缓存空 + core 不可达 ⇒ fail-closed(§6 第 6 行)
#              → 断言：伪造处方 ⇒ 仍 fail-closed（处方失败降 L2，L2 无缓存）
#              → 结束后**恢复 CR 并重启**，回到起点
#   P3：输出验收矩阵（PASS / FAIL / SKIPPED）与退出码
#
# 未覆盖（如实标注 SKIPPED 并给出原因）：
#   - "L2 命中 ⇒ 降级事件可观测（route_degraded 增长）" 需 gateway-core 可达并下发签名路由表；
#     本脚本不启动 gateway-core，故该项由逻辑层用例覆盖（route_decide_test.go / routecache_stale_test.go）。
#   - "验签失败 ⇒ 拒绝该表保留旧版本" 同理需拉取路径可达，由 routecache 单测覆盖。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\drill-core-degradation.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\drill-core-degradation.ps1 -EnableRouting
# 退出码：0 = 全部执行项 PASS；1 = 有 FAIL；2 = 脚本自身错误
#
# 注：UTF-8 with BOM（含中文，PS 5.1 按 ANSI 解析会破坏语法）。

param(
    [string]$Gateway = 'http://127.0.0.1:8080',
    [string]$Container = 'higress-chain-control-plane',
    [string]$CrFile = (Join-Path $PSScriptRoot '..\higress-standalone\wasmplugins\otpmask-1.0.0.yaml'),
    [string]$RouteKeyHex = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    [switch]$EnableRouting
)

$ErrorActionPreference = 'Stop'
$tmp = $env:TEMP
$results = New-Object System.Collections.ArrayList

function Record([string]$id, [string]$title, [string]$status, [string]$detail) {
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = $status; Detail = $detail })
    Write-Output ("[{0}] {1} - {2}" -f $status, $id, $title)
    if ($detail) { Write-Output ("        " + $detail) }
}

function Get-EnvoyStat([string]$name) {
    $out = docker exec $Container curl -s http://127.0.0.1:15000/stats 2>$null
    $line = $out | Select-String -Pattern ("wasmcustom\." + [regex]::Escape($name) + ":") | Select-Object -First 1
    if (-not $line) { return -1 }  # 指标未注册（懒初始化，未发生即不存在）
    return [int](($line.ToString() -split ':')[-1].Trim())
}

function Invoke-InferProbe([string]$bodyJson, [string]$rxToken) {
    $bodyFile = Join-Path $tmp 'drill-infer.json'
    [System.IO.File]::WriteAllText($bodyFile, $bodyJson, (New-Object System.Text.UTF8Encoding($false)))
    $outFile = Join-Path $tmp 'drill-infer.out'
    if (Test-Path $outFile) { Remove-Item $outFile -Force }
    # 请注意（踩坑记录）：① 原实现用 @args 展开的是 PS 自动变量 $args（未赋值）→ curl 收到空参数；
    # ② PS 5.1 对原生命令做数组 splat 时不会为含空格元素加引号（'Content-Type: application/json'
    # 会被拆成两个参数）。故此处逐条显式调用，且 header 值不含空格（X-Otp-Route:<token> 亦合法）。
    if ($rxToken) {
        $code = & curl.exe -s -m 30 -o $outFile -w '%{http_code}' -X POST "$Gateway/v1/infer" -H ("X-Otp-Route:" + $rxToken) --data-binary "@$bodyFile"
    } else {
        $code = & curl.exe -s -m 30 -o $outFile -w '%{http_code}' -X POST "$Gateway/v1/infer" --data-binary "@$bodyFile"
    }
    $curlExit = $LASTEXITCODE
    $body = ''
    if (Test-Path $outFile) { $body = (Get-Content $outFile -Raw) }
    $parsed = 0
    if ($code) { [void][int]::TryParse(($code | Select-Object -Last 1).ToString().Trim(), [ref]$parsed) }
    return [pscustomobject]@{ Code = $parsed; Body = $body; CurlExit = $curlExit }
}

function Wait-ContainerReady([int]$TimeoutSec = 120) {
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
    # 容器重启会杀掉 docker exec 起的 fork console（如有），尽力拉起，失败不影响演练判定
    $jar = '/tmp/fork-console-usage.jar'
    $has = docker exec $Container sh -c "test -f $jar && echo yes" 2>$null
    if ($has -match 'yes') {
        docker exec -d -e HIGRESS_CONSOLE_KUBE_CONFIG=/app/kubeconfig -e SERVER_PORT=18001 `
            -e ADMIN_SVC_TARGET=http://host.docker.internal:19095 `
            -e ADMIN_SVC_JWT_SECRET=admin-smoke-shared-secret-2026 `
            $Container java -jar $jar
    }
    return $ok
}

# ============ P1：路由未启用（只读，兼容性前提）============
Write-Output '===== P1 路由未启用：fail-closed 保持 + 降级指标不出现 ====='
$degradedBefore = Get-EnvoyStat 'otpmask_route_degraded_total'
$failBefore = Get-EnvoyStat 'otpmask_fail_closed_total'
$probe = Invoke-InferProbe '{"text":"drill-p1-probe"}'
$failAfter = Get-EnvoyStat 'otpmask_fail_closed_total'
$degradedAfter = Get-EnvoyStat 'otpmask_route_degraded_total'

if ($probe.Code -eq 0) {
    Record 'P1-1' '未启用路由时请求应 fail-closed（不静默直连）' 'FAIL' ("curl 调用失败（exit " + $probe.CurlExit + "），未取得 HTTP 状态")
} elseif ($probe.Code -ge 200 -and $probe.Code -lt 300) {
    Record 'P1-1' '未启用路由时请求应 fail-closed（不静默直连）' 'FAIL' ("实际 HTTP " + $probe.Code + "，body=" + $probe.Body)
} else {
    Record 'P1-1' '未启用路由时请求应 fail-closed（不静默直连）' 'PASS' ("HTTP " + $probe.Code + "，body=" + $probe.Body.Trim())
}
if ($failAfter -gt $failBefore) {
    Record 'P1-2' 'fail-closed 计数应因该请求增长' 'PASS' ("fail_closed " + $failBefore + " -> " + $failAfter)
} else {
    Record 'P1-2' 'fail-closed 计数应因该请求增长' 'FAIL' ("fail_closed 未增长（" + $failBefore + " -> " + $failAfter + "）")
}
if ($degradedAfter -lt 0 -and $degradedBefore -lt 0) {
    Record 'P1-3' '路由未启用时不应出现降级指标（说明未介入请求）' 'PASS' 'otpmask_route_degraded_total 未注册'
} elseif ($degradedAfter -le $degradedBefore) {
    Record 'P1-3' '路由未启用时降级计数不应增长' 'PASS' ("degraded " + $degradedBefore + " -> " + $degradedAfter)
} else {
    Record 'P1-3' '路由未启用时降级计数不应增长' 'FAIL' ("degraded " + $degradedBefore + " -> " + $degradedAfter)
}

# ============ P2：启用路由后 §6 第 6 行（core 不可达 + L2 空 ⇒ fail-closed）============
if (-not $EnableRouting) {
    Record 'P2-1' '启用路由：无处方 + 缓存空 + core 不可达 ⇒ fail-closed（§6 第 6 行）' 'SKIPPED' '未传 -EnableRouting（会临时改 CR 并重启容器）'
    Record 'P2-2' '启用路由：伪造处方 ⇒ 降级 L2 后仍 fail-closed' 'SKIPPED' '同上'
    Record 'P2-3' 'L2 命中 ⇒ 降级事件可观测（route_degraded 增长）' 'SKIPPED' '需 gateway-core 可达并下发签名路由表；逻辑层由 route_decide_test.go 覆盖'
    Record 'P2-4' '验签失败 ⇒ 拒绝该表、保留旧版本' 'SKIPPED' '同上；逻辑层由 routecache_test.go 覆盖'
} else {
    Write-Output '===== P2 启用路由（临时改 CR + 重启容器）====='
    if (-not (Test-Path $CrFile)) {
        Record 'P2-0' 'CR 文件存在' 'FAIL' ("未找到 " + $CrFile)
    } else {
        $backup = "$CrFile.drillbak"
        Copy-Item $CrFile $backup -Force
        try {
            $yaml = Get-Content $CrFile -Raw -Encoding UTF8
            if ($yaml -match 'gateway_core_enabled') {
                Record 'P2-0' 'CR 注入前置检查' 'FAIL' 'CR 已含 gateway_core_enabled（请先手工还原）'
            } else {
                $inject = @"
      gateway_core_enabled: true
      gateway_core_service: gateway-core
      gateway_core_port: 8085
      route_verify_key: $RouteKeyHex
      max_stale_seconds: 300
"@
                $repl = '${1}require_auth: false' + "`n" + $inject.TrimEnd()
                $yaml2 = $yaml -replace '(?m)^(\s*)require_auth: false\s*$', $repl
                if ($yaml2 -eq $yaml) {
                    Record 'P2-0' 'CR 注入' 'FAIL' '未找到 require_auth 锚点，未修改'
                } else {
                    [System.IO.File]::WriteAllText($CrFile, $yaml2, (New-Object System.Text.UTF8Encoding($false)))
                    $ready = Restart-Container
                    if (-not $ready) { Record 'P2-0' '容器重启就绪' 'FAIL' '超时' }

                    $d0 = Get-EnvoyStat 'otpmask_route_degraded_total'
                    $p1 = Invoke-InferProbe '{"text":"drill-p2-probe"}'
                    $d1 = Get-EnvoyStat 'otpmask_route_degraded_total'
                    if ($p1.Code -eq 503 -and $d1 -le $d0) {
                        Record 'P2-1' '启用路由：无处方 + 缓存空 + core 不可达 ⇒ fail-closed（§6 第 6 行）' 'PASS' ("HTTP 503，降级计数 " + $d0 + " -> " + $d1 + "（未命中不算降级）")
                    } else {
                        Record 'P2-1' '启用路由：无处方 + 缓存空 + core 不可达 ⇒ fail-closed（§6 第 6 行）' 'FAIL' ("HTTP " + $p1.Code + "，degraded " + $d0 + " -> " + $d1)
                    }

                    $p2 = Invoke-InferProbe '{"text":"drill-p2-fake-rx"}' 'ZmFrZS5wcmVzY3JpcHRpb24'
                    if ($p2.Code -eq 503) {
                        Record 'P2-2' '启用路由：伪造处方 ⇒ 降级 L2 后仍 fail-closed' 'PASS' 'HTTP 503'
                    } else {
                        Record 'P2-2' '启用路由：伪造处方 ⇒ 降级 L2 后仍 fail-closed' 'FAIL' ("HTTP " + $p2.Code)
                    }
                    Record 'P2-3' 'L2 命中 ⇒ 降级事件可观测（route_degraded 增长）' 'SKIPPED' '需 gateway-core 可达并下发签名路由表；逻辑层由 route_decide_test.go 覆盖'
                    Record 'P2-4' '验签失败 ⇒ 拒绝该表、保留旧版本' 'SKIPPED' '同上；逻辑层由 routecache_test.go 覆盖'
                }
            }
        } finally {
            if (Test-Path $backup) {
                Copy-Item $backup $CrFile -Force
                Remove-Item $backup -Force
                $ready2 = Restart-Container
                Record 'P2-9' '演练后恢复 CR 并重启' $(if ($ready2) { 'PASS' } else { 'FAIL' }) '已还原 baseline'
            }
        }
    }
}

# ============ P3：验收矩阵 ============
Write-Output ''
Write-Output '===== 验收矩阵（§6 降级与 fail-closed 语义）====='
$results | Format-Table -AutoSize | Out-String | Write-Output
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$skip = @($results | Where-Object { $_.Status -eq 'SKIPPED' }).Count
Write-Output ("汇总：PASS=" + $pass + " FAIL=" + $fail + " SKIPPED=" + $skip)
if ($fail -gt 0) { exit 1 }
exit 0
