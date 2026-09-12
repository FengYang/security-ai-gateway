#Requires -Version 5.1
<#
  check-higress-plugin-versions.ps1 —— Higress 插件版本门禁（防"静默不生效"漂移）

  背景：插件 URL 里的版本号一旦与镜像实际安装版本不一致，wasm 加载会 404；配合 FAIL_OPEN
        时请求被静默放行（认证/限流全部失效），线上不会明显报错，属"静默事故"。
        本项目已在 2026-09-12 实际踩到（3 个插件 1.x URL 在 2.x 镜像上全部 404）。

  校验两个方向：
    A. 仓库 ↔ 锁定文件：扫描仓库内全部 `plugins/<name>/<version>/plugin.wasm` 引用，
       与 deploy/higress/plugin-versions.lock 对照；未登记插件或版本不一致 → 失败。
    B. 锁定文件 ↔ 运行镜像（可选，传 -Container）：读镜像插件目录版本，与锁定文件对照；
       镜像升级导致版本漂移 → 失败（提醒同步清单与锁定文件）。

  用法：
    powershell -ExecutionPolicy Bypass -File scripts/check-higress-plugin-versions.ps1
    powershell -ExecutionPolicy Bypass -File scripts/check-higress-plugin-versions.ps1 -Container higress-chain-control-plane

  退出码：0 = 通过；1 = 存在未登记引用 / 版本漂移 / 锁定文件不可解析。
#>
param(
    [string]$LockFile = (Join-Path $PSScriptRoot '..\deploy\higress\plugin-versions.lock'),
    [string]$Root = (Join-Path $PSScriptRoot '..'),
    [string]$Container = ''
)

$ErrorActionPreference = 'Stop'
$fail = $false

# ---------- 1. 解析锁定文件 ----------
if (-not (Test-Path $LockFile)) {
    Write-Output "[FAIL] 锁定文件不存在：$LockFile"
    exit 1
}
$lock = @{}
foreach ($line in Get-Content $LockFile -Encoding UTF8) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    if ($t -notmatch '^([a-zA-Z0-9._-]+)=([0-9][0-9a-zA-Z.\-]*)$') {
        Write-Output "[FAIL] 锁定文件存在非法行：$t"
        $fail = $true
        continue
    }
    $lock[$Matches[1]] = $Matches[2]
}
Write-Output ("锁定插件数 = {0}" -f $lock.Count)

# ---------- 2. 方向 A：仓库引用 ↔ 锁定 ----------
$refs = New-Object System.Collections.Generic.List[object]
# 排除：vendor/node_modules/.git（非源码）与 higress-standalone（本地运行态快照目录，
# 其中 wasmplugins/*.yaml 由 Higress 控制台写入、会被覆盖，不作为"部署清单"校验对象）。
Get-ChildItem $Root -Recurse -File -Include *.yaml, *.yml, *.md, *.json, *.ps1, *.sh, *.go -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\vendor\\|\\node_modules\\|\\.git\\|\\higress-standalone\\' } |
    ForEach-Object {
        $rel = $_.FullName.Replace((Resolve-Path $Root).Path + '\', '')
        Select-String -Path $_.FullName -Pattern 'plugins/([a-zA-Z0-9._-]+)/([0-9][0-9a-zA-Z.\-]*)/plugin\.wasm' -AllMatches -ErrorAction SilentlyContinue |
            ForEach-Object {
                foreach ($m in $_.Matches) {
                    $refs.Add([pscustomobject]@{ Plugin = $m.Groups[1].Value; Version = $m.Groups[2].Value; File = $rel; Line = $_.LineNumber })
                }
            }
    }
Write-Output ("仓库内 plugin.wasm 引用 = {0}" -f $refs.Count)

$unknown = $refs | Where-Object { -not $lock.ContainsKey($_.Plugin) }
if ($unknown) {
    $fail = $true
    Write-Output "[FAIL] 未在锁定文件登记的插件引用："
    $unknown | Sort-Object Plugin, Version -Unique | ForEach-Object {
        Write-Output ("        {0} {1}   （{2}:{3}）" -f $_.Plugin, $_.Version, $_.File, $_.Line)
    }
}

$drift = $refs | Where-Object { $lock.ContainsKey($_.Plugin) -and $lock[$_.Plugin] -ne $_.Version }
if ($drift) {
    $fail = $true
    Write-Output "[FAIL] 版本与锁定文件不一致："
    $drift | Sort-Object Plugin, Version -Unique | ForEach-Object {
        Write-Output ("        {0}: 引用={1} 锁定={2}   （{3}:{4}）" -f $_.Plugin, $_.Version, $lock[$_.Plugin], $_.File, $_.Line)
    }
}

$referenced = $refs | Select-Object -ExpandProperty Plugin -Unique
$unused = $lock.Keys | Where-Object { $referenced -notcontains $_ }
if ($unused) {
    Write-Output ("[WARN] 锁定文件中未被仓库引用的条目（可能为预留/已停用）：{0}" -f (($unused | Sort-Object) -join ', '))
}

if (-not $fail) {
    $ok = $refs | Sort-Object Plugin, Version -Unique
    Write-Output "[PASS] 仓库引用与锁定文件一致："
    $ok | ForEach-Object { Write-Output ("        {0} = {1}" -f $_.Plugin, $_.Version) }
}

# ---------- 3. 方向 B（可选）：锁定 ↔ 运行镜像 ----------
if ($Container -ne '') {
    Write-Output ("--- 校验镜像插件版本（container={0}）---" -f $Container)
    $out = & docker exec $Container find /usr/share/nginx/html/plugins -mindepth 2 -maxdepth 2 -type d 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) {
        Write-Output "[WARN] 无法读取镜像插件目录（容器未运行或路径不同）；跳过方向 B"
    } else {
        $image = @{}
        foreach ($p in $out) {
            $seg = ($p -replace '^.*/plugins/', '') -split '/'
            if ($seg.Count -eq 2) { $image[$seg[0]] = $seg[1] }
        }
        Write-Output ("镜像插件数 = {0}" -f $image.Count)
        $imgDrift = @()
        foreach ($k in $lock.Keys) {
            if (-not $image.ContainsKey($k)) {
                $imgDrift += ("{0}: 镜像缺失（锁定={1}）" -f $k, $lock[$k])
            } elseif ($image[$k] -ne $lock[$k]) {
                $imgDrift += ("{0}: 锁定={1} 镜像={2}" -f $k, $lock[$k], $image[$k])
            }
        }
        if ($imgDrift.Count -gt 0) {
            $fail = $true
            Write-Output "[FAIL] 锁定文件与镜像版本漂移（镜像升级后需同步清单与锁定文件）："
            $imgDrift | ForEach-Object { Write-Output ("        " + $_) }
        } else {
            Write-Output "[PASS] 锁定文件与镜像版本一致"
        }
    }
}

if ($fail) { exit 1 }
Write-Output "[PASS] Higress 插件版本门禁通过"
exit 0
