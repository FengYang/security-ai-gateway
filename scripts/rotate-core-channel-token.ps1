# rotate-core-channel-token.ps1 — gateway-core 拉取通道令牌轮换（Phase 1 门禁 #7 / 边界 C）
#
# 背景：插件侧 CR 内不再出现通道令牌 —— 令牌由管理面只读端点按集合投递
# （GET /v1/adminext/credentials/core-channel，每集合独立读令牌），插件按 tick 热生效。
# 本脚本负责"改令牌文件 → 校验端点已投递新值 → （可选）校验插件已生效"。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\rotate-core-channel-token.ps1 `
#     -File deploy\secrets\gateway-core-token.env `
#     -Admin http://127.0.0.1:19095 -CredentialToken <core-channel 读令牌>
#   可选（校验插件侧已生效；需数据面容器在跑）：
#     -Container higress-chain-control-plane -WaitSeconds 60
#
# 步骤：
#   1) 生成 64 hex 新令牌（32 字节强度）
#   2) 备份旧文件 → 原子写（tmp + Move/overwrite）→ 尽力收紧权限（Windows 无 Unix 权限位语义，如实提示）
#   3) 复验管理面端点：core-channel 返回新令牌，且旧令牌不再返回
#   4) （可选）轮询数据面 stats：otpmask_core_channel_fetch_ok_total / otpmask_ratelimit_fetch_ok_total
#      在等待窗口内增长（= 插件已取到新令牌并成功拉表；旧令牌期间不中断）
#
# 退出码：0 = 成功；1 = 任一步失败；2 = 参数/环境错误
#
# 注：本脚本为 UTF-8 with BOM（含中文；PS 5.1 按 ANSI 解析会坏语法）。

param(
    [Parameter(Mandatory = $true)][string]$File,
    [Parameter(Mandatory = $true)][string]$Admin,
    [Parameter(Mandatory = $true)][string]$CredentialToken,
    [string]$SetName = 'core-channel',
    [string]$Container = '',
    [int]$WaitSeconds = 0
)

$ErrorActionPreference = 'Stop'

function Get-Json([string]$url, [string]$token) {
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = 'GET'
        $req.Timeout = 15000
        $req.Headers.Add('X-Credential-Token', $token)
        $resp = $req.GetResponse()
        $rd = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $t = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
        return @{ code = [int]$resp.StatusCode; body = $t }
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { return @{ code = [int]$r.StatusCode; body = '' } }
        return @{ code = -1; body = $_.Exception.Message }
    }
}

function Get-Stat([string]$container, [string]$name) {
    $out = & docker exec $container sh -c "curl -s http://127.0.0.1:15000/stats" 2>$null
    foreach ($line in ($out -split "`n")) {
        if ($line -match "^wasmcustom\.$([regex]::Escape($name)):\s*(\d+)") { return [int]$Matches[1] }
    }
    return -1
}

if (-not $File) { Write-Host '[FAIL] 需指定 -File' -ForegroundColor Red; exit 2 }
$dir = Split-Path -Parent $File
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

# 1) 新令牌（64 hex = 32 字节强度；与管理面 core-channel 下限 32 兼容）
$newToken = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
Write-Host "== 轮换 $SetName 通道令牌 ==" -ForegroundColor Cyan

$oldToken = $null
if (Test-Path $File) {
    foreach ($line in [System.IO.File]::ReadAllLines($File)) {
        if ($line -match '^\s*token\s*=\s*(.+)$') { $oldToken = $Matches[1].Trim() }
    }
    $bak = "$File.bak-" + (Get-Date -Format 'yyyyMMddHHmmss')
    Copy-Item -LiteralPath $File -Destination $bak -Force
    Write-Host "  备份: $bak" -ForegroundColor DarkGray
}

# 2) 原子写（tmp + Move/overwrite）：避免插件读到半截文件
$tmp = "$File.tmp"
[System.IO.File]::WriteAllText($tmp, "token=$newToken`n", (New-Object System.Text.UTF8Encoding($false)))
Move-Item -LiteralPath $tmp -Destination $File -Force
Write-Host "  已写入: $File（len=$($newToken.Length)）" -ForegroundColor Green

# 权限收紧：Windows 无 Unix 权限位语义 —— 尽力用 ACL 限制为当前用户（失败仅提示，不阻断）
if ($env:OS -eq 'Windows_NT') {
    try {
        & icacls $File /inheritance:r /grant:r "$($env:USERNAME):(R,W)" *> $null
        Write-Host '  权限: 已尽力收紧为当前用户（Windows 无 0600 语义，如实说明）' -ForegroundColor DarkGray
    } catch {
        Write-Host '  权限: 收紧失败（不阻断；生产建议由 Secret 挂载替代本地文件）' -ForegroundColor DarkYellow
    }
} else {
    & chmod 600 $File
    Write-Host '  权限: 已设为 0600' -ForegroundColor DarkGray
}

# 3) 复验管理面端点
$url = "$Admin/v1/adminext/credentials/$SetName"
$r = Get-Json $url $CredentialToken
if ($r.code -ne 200) {
    Write-Host "[FAIL] 端点复验失败：GET $url -> $($r.code)（${SetName} 读令牌是否正确？端点是否注册？）" -ForegroundColor Red
    exit 1
}
$served = $null
try { $served = (($r.body | ConvertFrom-Json).token) } catch { }
if ($served -ne $newToken) {
    Write-Host "[FAIL] 端点未投递新令牌（可能缓存/权限问题）" -ForegroundColor Red
    exit 1
}
if ($oldToken -and $oldToken -eq $served) {
    Write-Host '[FAIL] 端点仍返回旧令牌' -ForegroundColor Red
    exit 1
}
Write-Host "  [PASS] 端点已投递新令牌（$url）" -ForegroundColor Green

# 4) 可选：校验插件侧已生效（stats 增长）
if ($Container -ne '' -and $WaitSeconds -gt 0) {
    $okBefore = Get-Stat $Container 'otpmask_core_channel_fetch_ok_total'
    $rlBefore = Get-Stat $Container 'otpmask_ratelimit_fetch_ok_total'
    Write-Host "  等待插件生效（最多 ${WaitSeconds}s）: cred_ok=$okBefore ratelimit_ok=$rlBefore" -ForegroundColor DarkGray
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $credGrew = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $okNow = Get-Stat $Container 'otpmask_core_channel_fetch_ok_total'
        if ($okBefore -ge 0 -and $okNow -gt $okBefore) { $credGrew = $true; break }
    }
    $rlAfter = Get-Stat $Container 'otpmask_ratelimit_fetch_ok_total'
    if (-not $credGrew) {
        Write-Host "[FAIL] 插件未在窗口内取到新令牌（cred_ok 未增长；检查 credential_token 与集合名）" -ForegroundColor Red
        exit 1
    }
    Write-Host "  [PASS] 插件已生效：cred_ok=$((Get-Stat $Container 'otpmask_core_channel_fetch_ok_total'))" -ForegroundColor Green
    if ($rlBefore -ge 0 -and $rlAfter -le $rlBefore) {
        Write-Host '  [WARN] 限流表拉取 ok 计数未增长（可能下一 tick 才刷新；不等于失败）' -ForegroundColor DarkYellow
    } else {
        Write-Host "  [PASS] 限流表拉取继续 ok（$rlBefore → $rlAfter）——轮换不停机" -ForegroundColor Green
    }
} elseif ($Container -ne '') {
    Write-Host '  [跳过] 未指定 -WaitSeconds > 0，不做插件侧生效校验' -ForegroundColor DarkYellow
}

exit 0
