# rotate-otpmask-keys.ps1 - 段① 凭据轮换编排（Phase 1 门禁 #8）
#
# 定位：改写管理面凭据文件（sig_key / attest_token）→ 插件按 credential_interval 周期热拉取
#       → 轮换窗口内持续探活，断言**服务不停机**（无 5xx）。
#
# 背景与设计见 deploy/higress/README.md §6.1：
#   - 插件端点：GET {admin}/v1/adminext/credentials/otpmask-keys（头 X-Credential-Token）
#   - 失败策略＝保留旧值（非 fail-closed 丢弃），故轮换期间不应出现 5xx
#   - 通道＝内网 + 受限读取令牌（明文），属评审选定口径
#
# 用法：
#   # 1) 首次初始化（生成 sig_key 与 attest_token）
#   powershell -ExecutionPolicy Bypass -File scripts\rotate-otpmask-keys.ps1 -Init
#   # 2) 轮换（保留 attest_token，仅换 sig_key）并做不停机探活
#   powershell -ExecutionPolicy Bypass -File scripts\rotate-otpmask-keys.ps1 `
#       -Gateway http://127.0.0.1:8080 -WaitSeconds 320
#   # 3) 只改文件不探活（如 tee-infer 侧需同步时先离线准备）
#   powershell -ExecutionPolicy Bypass -File scripts\rotate-otpmask-keys.ps1 -SkipProbe
#
# 退出码：0 = 成功；1 = 存在 FAIL；2 = 脚本自身错误
#
# 注：本脚本须为 UTF-8 with BOM（含中文；PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$CredentialFile = '',
    [string]$SigKeyHex = '',
    [string]$AttestToken = '',
    [string]$Gateway = '',
    [int]$WaitSeconds = 320,
    [int]$ProbeEverySeconds = 5,
    [int]$WarmMaxAttempts = 24,
    [switch]$Init,
    [switch]$SkipProbe
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $CredentialFile) { $CredentialFile = Join-Path $repo 'deploy\secrets\otpmask-keys.env' }

$results = New-Object System.Collections.ArrayList
function Record([string]$id, [string]$title, [bool]$ok, [string]$detail) {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = $tag; Detail = $detail })
    Write-Host ("[{0}] {1} - {2}" -f $tag, $id, $title) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if ($detail) { Write-Host ("        " + $detail) -ForegroundColor DarkGray }
}

function New-HexKey([int]$bytes = 32) {
    $buf = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buf)
    return (($buf | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Read-CredFile([string]$path) {
    $out = @{ sig_key = ''; attest_token = '' }
    if (-not (Test-Path $path)) { return $out }
    foreach ($line in [System.IO.File]::ReadAllLines($path)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $i = $t.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $t.Substring(0, $i).Trim(); $v = $t.Substring($i + 1).Trim()
        if ($k -eq 'sig_key') { $out.sig_key = $v }
        elseif ($k -eq 'attest_token') { $out.attest_token = $v }
    }
    return $out
}

function Write-CredFile([string]$path, [string]$sigKey, [string]$attest) {
    $dir = Split-Path -Parent $path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $content = "# 段① 凭据（Phase 1 门禁 #8）——运行态拉取源；勿入库（deploy/secrets 已 gitignore）`n" +
               "sig_key=$sigKey`nattest_token=$attest`n"
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $content, (New-Object System.Text.UTF8Encoding($false)))
    if ($env:OS -ne 'Windows_NT') {
        try { chmod 600 $tmp } catch { }
    }
    Move-Item -Force $tmp $path
}

function Invoke-InferProbe([string]$gw) {
    $body = '{"model":"mock","engine_type":"cmaas","messages":[{"role":"user","content":"凭据轮换探活"}]}'
    $tmp = Join-Path $env:TEMP 'rotate-probe.json'
    [System.IO.File]::WriteAllText($tmp, $body, (New-Object System.Text.UTF8Encoding($false)))
    $code = & curl.exe -s -o NUL -m 60 -w '%{http_code}' -X POST "$gw/v1/infer" `
        -H 'Content-Type: application/json' --data-binary "@$tmp" 2>$null
    return "$code".Trim()
}

Write-Host '===== 段① 凭据轮换（门禁 #8）=====' -ForegroundColor Cyan
Write-Host "CredentialFile=$CredentialFile Init=$Init SkipProbe=$SkipProbe Gateway=$(if($Gateway){$Gateway}else{'(未指定) '})"

# ---------- 生成/解析新凭据 ----------
$existing = Read-CredFile $CredentialFile
if (-not $SigKeyHex) { $SigKeyHex = New-HexKey 32 }
if (-not $AttestToken) { $AttestToken = if ($existing.attest_token) { $existing.attest_token } else { '' } }

if ($Init) {
    if (-not $AttestToken) { $AttestToken = New-HexKey 16 }
    Record 'A1' '初始化模式：生成 sig_key 与 attest_token' $true "sig_key(hex,len)=$($SigKeyHex.Length) attest_token(len)=$($AttestToken.Length)"
} else {
    Record 'A1' '轮换模式：生成新 sig_key（attest_token 沿用原值）' ([bool]$AttestToken) `
        "sig_key(hex,len)=$($SigKeyHex.Length) attest_token=$($AttestToken.Length)字符"
}

if ($AttestToken.Length -lt 8) {
    Record 'A2' 'attest_token 可用（长度 ≥8）' $false '缺少 attest_token：请用 -Init 首次生成，或显式传 -AttestToken'
} else {
    Record 'A2' 'attest_token 可用（长度 ≥8）' $true ''
}

# ---------- 原子写入 ----------
try {
    Write-CredFile $CredentialFile $SigKeyHex $AttestToken
    $after = Read-CredFile $CredentialFile
    $ok = ($after.sig_key -eq $SigKeyHex) -and ($after.attest_token -eq $AttestToken)
    Record 'A3' '凭据文件已原子写入（tmp+rename）' $ok "path=$CredentialFile"
} catch {
    Record 'A3' '凭据文件已原子写入（tmp+rename）' $false $_.Exception.Message
}

# ---------- 与 tee-infer 侧一致性提醒（不自动改远端） ----------
Write-Host "`n[提醒] token 模式下 sig_key/attest_token 必须与 tee-infer 侧一致；" -ForegroundColor Yellow
Write-Host "       轮换后请同步 tee-infer 的 otpmask-keys Secret（deploy/higress/otpmask-secret.yaml），" -ForegroundColor Yellow
Write-Host "       或改用 attest_mode=quote（生产推荐，二者不参与会话密钥派生）。" -ForegroundColor Yellow

# ---------- 不停机探活 ----------
if (-not $SkipProbe -and $Gateway) {
    Write-Host "`n===== 不停机探活（轮换窗口内持续请求）=====" -ForegroundColor Cyan
    # 预热：TEE/插件会话恢复期可能出现 503（逐 worker 重握手），不计入轮换判定
    $streak = 0; $warm = -1
    for ($i = 1; $i -le $WarmMaxAttempts; $i++) {
        if ((Invoke-InferProbe $Gateway) -eq '200') { $streak++ } else { $streak = 0 }
        if ($streak -ge 3) { $warm = $i; break }
    }
    Record 'V1' '预热收敛（连续 3 次 200）' ($warm -gt 0) "第 $warm 次收敛"

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $probes = 0; $bad = @()
    while ((Get-Date) -lt $deadline) {
        $c = Invoke-InferProbe $Gateway
        $probes++
        if ($c -ne '200') { $bad += $c }
        Start-Sleep -Seconds $ProbeEverySeconds
    }
    Record 'V2' "轮换窗口内 $probes 次探活全部 200（服务不停机）" ($bad.Count -eq 0) `
        $(if ($bad.Count -eq 0) { "窗口 ${WaitSeconds}s / 间隔 ${ProbeEverySeconds}s" } else { "异常码: $(($bad | Group-Object | ForEach-Object { $_.Name + 'x' + $_.Count }) -join ',')" })
} elseif (-not $SkipProbe) {
    Write-Host "`n[跳过] 未指定 -Gateway，未做不停机探活（可传 -Gateway 补做）" -ForegroundColor DarkYellow
}

# ---------- 汇总 ----------
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
Write-Host "PASS=$pass FAIL=$fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "提示：插件生效时机 = credential_interval（缺省 300s）；验证生效可查 otpmask_cred_fetch_ok_total 指标。" -ForegroundColor DarkGray
if ($fail -gt 0) { exit 1 }
exit 0
