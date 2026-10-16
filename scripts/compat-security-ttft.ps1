# scripts/compat-security-ttft.ps1 — P1-6 M6.6 兼容与安全测试运行器
#
# 依据：本体 v1.5 §9.1「兼容测试」「安全测试」+ §4.1 M6.6。
# 被测：
#   - gateway/gateway-core/internal/api/ttft_compat_security_test.go（安全：鉴权/跨租户/注入钳制；兼容：旧表 API 往返）
#   - gateway/wasm/otpmask-plugin/compat_test.go（兼容：旧表引擎配置缺省；/metrics 既有名与桶命名冻结）
#
# 用法：
#   pwsh scripts/compat-security-ttft.ps1
#
# 退出码：0 = 两模块兼容/安全用例全通过；1 = 存在失败。

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
	Write-Output '=== P1-6 M6.6 兼容与安全测试（§9.1）==='

	Write-Output ''
	Write-Output '[安全/兼容 · 控制面] gateway-core/internal/api'
	$coreOut = @(& go test -count 1 -run 'TestTTFT_Security|TestTTFT_Compat' -v ./gateway/gateway-core/internal/api/ 2>&1 | ForEach-Object { "$_" })
	$coreCode = $LASTEXITCODE

	Write-Output ''
	Write-Output '[兼容 · 数据面] otpmask-plugin（配置映射 + 指标命名冻结）'
	$plugOut = @(& go test -count 1 -run 'TestCompat_' -v ./gateway/wasm/otpmask-plugin/ 2>&1 | ForEach-Object { "$_" })
	$plugCode = $LASTEXITCODE

	$pass = 0
	$fail = 0
	foreach ($l in @($coreOut) + @($plugOut)) {
		if ($l -match '^--- PASS:\s+(\S+)') { $pass++; Write-Output ("  [PASS] " + $Matches[1]) }
		elseif ($l -match '^--- FAIL:\s+(\S+)') { $fail++; Write-Output ("  [FAIL] " + $Matches[1]) }
		elseif ($l -match '_test\.go:\d+:') { Write-Output ("  " + ($l -replace '^\s+', '')) }
	}

	Write-Output ''
	if ($coreCode -ne 0 -or $plugCode -ne 0 -or $fail -gt 0 -or $pass -eq 0) {
		Write-Output ("=== 结果：FAIL（通过 {0}，失败 {1}；core exit={2} plugin exit={3}）===" -f $pass, $fail, $coreCode, $plugCode)
		exit 1
	}
	Write-Output ("=== 结果：PASS（{0} 个用例全通过）===" -f $pass)
}
finally {
	Pop-Location
}
