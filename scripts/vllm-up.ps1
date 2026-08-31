# vllm-up.ps1 - vLLM 密态对接一键接入（GPU 前置，N1）
#
# GPU 环境：后台启动真实 vLLM 适配器（vllm_adapter.py --model）→ tee-infer 接线 engine-url → 链路验证
# 本地验证：后台启动 Go mock 适配器（复用 tee-infer 本地模型）→ 同上
#
# 用法：
#   powershell -File scripts/vllm-up.ps1 -Mode Gpu    -Model Qwen/Qwen2.5-7B-Instruct   # GPU 真实引擎
#   powershell -File scripts/vllm-up.ps1 -Mode Mock                                         # 本地 mock 验证
#   powershell -File scripts/vllm-up.ps1 -Mode Status                                       # 接线/适配器状态
#   powershell -File scripts/vllm-up.ps1 -Mode TearDown                                     # 停适配器 + 还原
#
# 说明：docker compose 场景下 tee-infer 在容器内，经 host.docker.internal 访问宿主适配器。

param(
    [ValidateSet('Gpu', 'Mock', 'Status', 'TearDown')]
    [string]$Mode = 'Mock',
    [string]$Model = 'Qwen/Qwen2.5-7B-Instruct',
    [int]$AdapterPort = 19190
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$go = $env:GO_BIN
if (-not $go) {
    $g = Get-Command go -ErrorAction SilentlyContinue
    if ($g) { $go = $g.Source } else { $go = 'C:\Program Files\Go\bin\go.exe' }
}
$COMPOSE = Join-Path $root 'gateway\wasm\otpmask-plugin\docker-compose.yaml'
$COMPOSE_DIR = Join-Path $root 'gateway\wasm\otpmask-plugin'
$ADAPTER_HOST = "http://host.docker.internal:$AdapterPort"
$PID_FILE = Join-Path $env:TEMP 'otpmask-vllm-adapter.pid'

function Set-EngineUrl {
    param([bool]$Enabled)
    $text = [System.IO.File]::ReadAllText($COMPOSE)
    if ($Enabled) {
        if (-not $text.Contains('-engine-url')) {
            # 定位 attest-token 值行行尾（兼容 CRLF/LF），在其后插入 engine-url
            $idx = $text.IndexOf('"-attest-token"')
            if ($idx -lt 0) { throw 'compose 中未找到 attest-token 锚点' }
            $keyNl = $text.IndexOf("`n", $idx)
            if ($keyNl -lt 0) { throw 'compose 解析失败（键行无行尾）' }
            $rest = $text.Substring($keyNl + 1)
            $valNl = $rest.IndexOf("`n")
            $ins = $keyNl + 1 + $(if ($valNl -lt 0) { $rest.Length } else { $valNl })
            $insert = "`n    - `"-engine-url`"`n    - `"$ADAPTER_HOST`""
            $text = $text.Substring(0, $ins) + $insert + $text.Substring($ins)
            [System.IO.File]::WriteAllText($COMPOSE, $text, (New-Object System.Text.UTF8Encoding $false))
            Write-Host "[vllm] tee-infer 已接线 engine-url=$ADAPTER_HOST"
        }
    } else {
        if ($text.Contains('-engine-url')) {
            $text = $text -replace '\s+-\s+"-engine-url"\s+-\s+"[^"]+"', ''
            [System.IO.File]::WriteAllText($COMPOSE, $text, (New-Object System.Text.UTF8Encoding $false))
            Write-Host "[vllm] tee-infer 已还原（本地模拟引擎）"
        }
    }
}

function Start-Adapter {
    if ($Mode -eq 'Gpu') {
        $py = Join-Path $root 'gateway\vllm-adapter\vllm_adapter.py'
        Write-Host "[vllm] 启动真实 vLLM 适配器（model=$Model，需 GPU，pip install vllm）..."
        return Start-Process -FilePath 'python' -ArgumentList @($py, '--model', $Model, '--listen', ":${AdapterPort}") -WindowStyle Hidden -PassThru
    }
    $dir = Join-Path $root 'gateway\vllm-adapter'
    Write-Host "[vllm] 启动 Go mock 适配器（复用本地模型）..."
    return Start-Process -FilePath $go -ArgumentList @('run', $dir, '-listen', ":${AdapterPort}") -WindowStyle Hidden -PassThru
}

function Wait-Adapter {
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $h = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:${AdapterPort}/health" -TimeoutSec 2 -ErrorAction Stop
            if ($h) { return $true }
        } catch { Start-Sleep -Seconds 1 }
    }
    return $false
}

switch ($Mode) {
    'Status' {
        $wired = [System.IO.File]::ReadAllText($COMPOSE).Contains('-engine-url')
        Write-Host "[vllm] engine-url 接线: $wired"
        try {
            $h = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:${AdapterPort}/health" -TimeoutSec 3
            Write-Host "[vllm] 适配器: $($h.Content)"
        } catch { Write-Host '[vllm] 适配器未运行' }
        exit 0
    }
    'TearDown' {
        if (Test-Path $PID_FILE) {
            $procId = [int](Get-Content $PID_FILE)
            try { Stop-Process -Id $procId -Force -ErrorAction Stop; Write-Host "[vllm] 适配器进程 $procId 已停止" } catch { Write-Host '[vllm] 适配器进程已不存在' }
            Remove-Item $PID_FILE -ErrorAction SilentlyContinue
        }
        Set-EngineUrl $false
        Push-Location $COMPOSE_DIR
        docker compose up -d --build tee-infer-service | Out-Null
        Pop-Location
        Write-Host '[vllm] 已还原：tee-infer 回到本地模拟引擎'
        exit 0
    }
}

# 接线 + 启动适配器 + 验证
Set-EngineUrl $true
$proc = Start-Adapter
$proc.Id | Out-File -FilePath $PID_FILE -Encoding ascii
if (-not (Wait-Adapter)) {
    Write-Host '[FAIL] 适配器未就绪（Gpu 模式检查 GPU/vLLM 安装；Mock 模式检查 Go 编译）' -ForegroundColor Red
    exit 1
}
Write-Host "[vllm] 适配器就绪: http://127.0.0.1:${AdapterPort}/health"

Write-Host '[vllm] 重建 tee-infer-service（加载 engine-url）...'
Push-Location $COMPOSE_DIR
docker compose up -d --build tee-infer-service | Out-Null
Pop-Location
Start-Sleep -Seconds 6

# 链路验证：经网关推理应 200 SSE（python 探测，兼容 SSE 流式响应）
$pyProbe = @"
import urllib.request, json
r = urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:10000/infer',
    data=json.dumps({'text': 'vllm wiring check'}).encode,
    headers={'Content-Type': 'application/json'}), timeout=20)
b = r.read.decode
print(r.status, 'data: [DONE]' in b)
"@
$probeOut = python -c $pyProbe 2>&1 | Out-String
if ($probeOut -match '200 True') { Write-Host '[PASS] vLLM 接线链路验证通过（网关 200 SSE）'; exit 0 }
Write-Host "[FAIL] 网关链路验证失败: $($probeOut.Trim)" -ForegroundColor Red
exit 1
