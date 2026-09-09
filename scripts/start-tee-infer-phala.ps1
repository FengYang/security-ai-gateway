# 启动 tee-infer-service 并对接 Phala 密态推理网关（R1-B 预演线）。
# 密钥从 deploy/secrets/cmaas.env 读取（gitignored），经环境变量注入，
# 不出现在命令行与进程列表。
#
# 用法：.\scripts\start-tee-infer-phala.ps1 [-Port 8090]

param(
    [int]$Port = 8090
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $repoRoot "deploy\secrets\cmaas.env"

if (-not (Test-Path $envFile)) {
    Write-Error "配置文件不存在: $envFile（请参照文件头注释创建，密钥不入库）"
}

# 解析 KEY=VALUE 配置（忽略注释与空行）
# -Encoding UTF8：文件为 UTF-8（含中文注释）；PS 5.1 默认按 ANSI 解码，多字节
# 序列可能吞掉行尾 CRLF 并把下一行 KEY 合并进注释行，导致密钥解析丢失
$config = @{}
Get-Content $envFile -Encoding UTF8 | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $k, $v = $line -split "=", 2
        if ($k -and $v) { $config[$k.Trim()] = $v.Trim() }
    }
}

if (-not $config["CMAAS_URL"] -or -not $config["CMAAS_API_KEY"]) {
    Write-Error "配置不完整：CMAAS_URL 与 CMAAS_API_KEY 必填（见 $envFile）"
}

# 密钥与环境注入（子进程可见；不回显明文 key）
$env:CMAAS_API_KEY = $config["CMAAS_API_KEY"]
Write-Host ("[start] CMAAS_URL=" + $config["CMAAS_URL"] + "  CMAAS_MODEL=" + $config["CMAAS_MODEL"] + "  API_KEY=***" + $config["CMAAS_API_KEY"].Substring([Math]::Max(0, $config["CMAAS_API_KEY"].Length - 4)))

$goArgs = @(
    "run", "./gateway/tee-infer-service",
    "-listen", ":$Port",
    "-cmaas-url", $config["CMAAS_URL"],
    "-cmaas-model", $config["CMAAS_MODEL"]
)

Write-Host "[start] 启动 tee-infer-service（:$Port，密钥经 env 注入）"
& go @goArgs
