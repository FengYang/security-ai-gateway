# canary-release.ps1 - tee-infer-service 金丝雀发布 / 回滚（C-7）
#
# 原理：canary Deployment 与稳定版共用 Service 选择器（app: tee-infer-service），
#       副本数比例即流量比例（无集群时支持 -DryRun 打印将执行的命令）。
#
# 用法（需 kubectl + 集群）：
#   powershell -File scripts/canary-release.ps1 -Action deploy  -Tag v2.0.0     # 部署 canary（新 tag）
#   powershell -File scripts/canary-release.ps1 -Action weight -Canary 1 -Stable 2  # 1/3 流量给 canary
#   powershell -File scripts/canary-release.ps1 -Action promote                 # 稳定版升级新 tag，收 canary
#   powershell -File scripts/canary-release.ps1 -Action rollback -Tag v1.0.0    # 回滚稳定版，收 canary
#   powershell -File scripts/canary-release.ps1 -Action status                  # 当前副本/镜像状态
#   powershell -File scripts/canary-release.ps1 -Action deploy -Tag v2.0.0 -DryRun  # 无集群演练

param(
    [ValidateSet('deploy', 'weight', 'promote', 'rollback', 'status')]
    [string]$Action,
    [string]$Tag = 'latest',
    [int]$Canary = 1,
    [int]$Stable = 2,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$NS = 'otpmask'
$STABLE_DEP = 'tee-infer-service'
$CANARY_DEP = 'tee-infer-canary'
$TMPL = Join-Path $root 'deploy\k8s\canary\tee-infer-canary.yaml'

function ExecKubectl {
    param([string]$CmdLine)
    if ($DryRun) { Write-Host "[dry-run] kubectl $CmdLine"; return }
    Invoke-Expression "kubectl $CmdLine"
}

switch ($Action) {
    'deploy' {
        if ($Tag -eq 'latest') { throw 'deploy 需指定 -Tag（如 v2.0.0）' }
        $yaml = (Get-Content -Raw -Encoding UTF8 $TMPL).Replace('__TAG__', $Tag)
        $tmp = Join-Path $env:TEMP 'tee-infer-canary.yaml'
        [System.IO.File]::WriteAllText($tmp, $yaml, (New-Object System.Text.UTF8Encoding $false))
        if ($DryRun) { Write-Host "[dry-run] kubectl apply -f $tmp (image tag=$Tag)" }
        else { ExecKubectl "apply -f $tmp" }
        Write-Host "canary 已部署（tag=$Tag）；下一步：-Action weight 调整流量比例"
    }
    'weight' {
        ExecKubectl "scale deployment $STABLE_DEP -n $NS --replicas=$Stable"
        ExecKubectl "scale deployment $CANARY_DEP -n $NS --replicas=$Canary"
        $total = $Stable + $Canary
        $pct = [math]::Round($Canary * 100.0 / $total, 1)
        Write-Host "流量比例：canary $Canary/$total（约 $pct%） stable $Stable/$total"
    }
    'promote' {
        if ($Tag -eq 'latest') { throw 'promote 需指定 -Tag（稳定版目标版本）' }
        ExecKubectl "set image deployment/$STABLE_DEP -n $NS tee-infer-service=otpmask/tee-infer-service:$Tag"
        ExecKubectl "scale deployment $CANARY_DEP -n $NS --replicas=0"
        Write-Host "稳定版已升级到 $Tag，canary 已收量（保留 Deployment 便于快速回滚）"
    }
    'rollback' {
        if ($Tag -eq 'latest') { throw 'rollback 需指定 -Tag（回滚目标版本）' }
        ExecKubectl "set image deployment/$STABLE_DEP -n $NS tee-infer-service=otpmask/tee-infer-service:$Tag"
        ExecKubectl "scale deployment $CANARY_DEP -n $NS --replicas=0"
        Write-Host "已回滚稳定版到 $Tag，canary 收量"
    }
    'status' {
        ExecKubectl "get deploy $STABLE_DEP,$CANARY_DEP -n $NS -o wide"
        ExecKubectl "get pods -n $NS -l app=tee-infer-service -o wide"
    }
}
