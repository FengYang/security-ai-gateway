#Requires -Version 5.1
<#
  build-qwen3guard-plugin.ps1 —— 构建 Qwen3Guard 内容安全 Wasm 插件（自托管路线）

  背景：上游不提供 qwen3guard 的预构建镜像（Higress 官方插件仓库亦无此插件，已实测确认），
        且本项目需支持内网/离线部署，故源码已内置 gateway/wasm/qwen3guard-plugin/，
        构建仅依赖 Go 与模块依赖（可预置模块缓存后离线构建）。

  用法：
    powershell -ExecutionPolicy Bypass -File scripts/build-qwen3guard-plugin.ps1
    # 若需同时投放本地网关（bind-mount 约定路径），追加：
    powershell -ExecutionPolicy Bypass -File scripts/build-qwen3guard-plugin.ps1 -DeployContainer higress-chain-control-plane

  产物：gateway/wasm/qwen3guard-plugin/main.wasm（*.wasm 已被 .gitignore 忽略，不入库）
  退出码：0 成功；1 构建失败或产物缺失。
#>
param(
    [string]$DeployContainer = '',
    [string]$PluginVersion = '1.0.0'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'gateway\wasm\qwen3guard-plugin'
$out = Join-Path $src 'main.wasm'

if (-not (Test-Path (Join-Path $src 'go.mod'))) {
    Write-Output "[FAIL] 未找到插件源码：$src"
    exit 1
}

Write-Output "== 构建 qwen3guard 插件（wasip1 / c-shared）=="
Push-Location $src
try {
    $env:GOOS = 'wasip1'
    $env:GOARCH = 'wasm'
    # -trimpath     ：去掉二进制内嵌的绝对源码路径
    # -buildvcs=false：不嵌入 VCS 信息（否则仓库内构建会写入 git revision/modified，导致
    #                  "仓库内 vs 仓库外"产出不同哈希 —— 实测踩到过）
    # 两者共同保证「不同构建目录产出同一哈希」，便于内网交付时按哈希核对产物。
    & go build -mod=mod -trimpath -buildvcs=false -buildmode=c-shared -o $out .
    $code = $LASTEXITCODE
} finally {
    Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}

if ($code -ne 0 -or -not (Test-Path $out)) {
    Write-Output "[FAIL] 构建失败（exit=$code）"
    exit 1
}
$f = Get-Item $out
$sha = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
Write-Output ("[PASS] 产物：{0}  {1} bytes" -f $f.FullName, $f.Length)
Write-Output ("       sha256 = {0}" -f $sha)

if ($DeployContainer -ne '') {
    $containerPath = "/usr/share/nginx/html/plugins/qwen3guard/$PluginVersion/plugin.wasm"
    Write-Output ("== 投放本地网关（{0} → 容器 {1}）==" -f $DeployContainer, $containerPath)
    & docker exec $DeployContainer mkdir -p ("/usr/share/nginx/html/plugins/qwen3guard/" + $PluginVersion)
    & docker cp $out ("{0}:{1}" -f $DeployContainer, $containerPath)
    if ($LASTEXITCODE -ne 0) {
        Write-Output "[FAIL] docker cp 失败"
        exit 1
    }
    Write-Output "[PASS] 已投放；WasmPlugin 引用 URL：http://localhost:8002/plugins/qwen3guard/$PluginVersion/plugin.wasm"
    Write-Output "       注意：容器内新投放的插件目录在容器重建后会丢失，重建后需重新执行本步骤"
}
exit 0
