# scripts/chaos-ttft.ps1 — P1-6 M6.5 模型抖动混沌测试运行器（SC-1..SC-5）
#
# 依据：本体 v1.5 §9.1 / V-8（量化断言）+ §4.1 M6.5（落点 scripts/）。
# 被测实现：gateway/wasm/otpmask-plugin/routeengine/chaos_test.go（TestChaos_SC*）。
#
# 用法：
#   pwsh scripts/chaos-ttft.ps1            # 单次
#   pwsh scripts/chaos-ttft.ps1 -Count 3   # 连跑 3 次（稳定性复核）
#
# 退出码：0 = 5 场景全通过；1 = 存在失败或未全部执行。

[CmdletBinding()]
param([int]$Count = 1)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
	Write-Output '=== P1-6 M6.5 模型抖动混沌测试（SC-1..SC-5，§9.1/V-8）==='
	Write-Output ("[参数] count={0}  场景：SC-1 单端点劣化 / SC-2 周期抖动 / SC-3 全体劣化 / SC-4 统计中断 / SC-5 单端点变快" -f $Count)

	$out = @(& go test -count $Count -run 'TestChaos_SC' -v ./gateway/wasm/otpmask-plugin/routeengine/ 2>&1 | ForEach-Object { "$_" })
	$code = $LASTEXITCODE

	$pass = 0
	$fail = 0
	foreach ($l in $out) {
		if ($l -match 'chaos_test\.go:\d+:\s*(SC-\d.*)$') {
			Write-Output ("  " + $Matches[1])
		}
		elseif ($l -match '^--- PASS:\s+(TestChaos_SC\S+)') {
			$pass++
			Write-Output ("  [PASS] " + $Matches[1])
		}
		elseif ($l -match '^--- FAIL:\s+(TestChaos_SC\S+)') {
			$fail++
			Write-Output ("  [FAIL] " + $Matches[1])
		}
	}

	Write-Output ''
	if ($code -ne 0 -or $fail -gt 0 -or $pass -eq 0) {
		Write-Output ("=== 结果：FAIL（通过 {0}，失败 {1}，go test exit={2}）===" -f $pass, $fail, $code)
		exit 1
	}
	Write-Output ("=== 结果：PASS（{0} 个用例全通过）===" -f $pass)
}
finally {
	Pop-Location
}
