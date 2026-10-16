# scripts/bench-ttft.ps1 — P1-6 M6.4 性能基准门禁（选路 < 20us；body 采样 < 3%）
#
# 门禁口径（如实注记）：
#   1) 选路：latency-aware / latency-fastest / hybrid 的 PickEndpoint 单次耗时 < 20us/op
#      （本体 §7.7/§9.1；对比同规模非延迟策略基线，报告净增，不设门禁）。
#   2) body 采样：以 1k token 流式响应为基准，采样路径净增 CPU / 参考流时长 < 3%。
#      参考流时长 = 1000 token × -StreamMsPerToken（默认 15ms/token = 15000ms）。
#      同时报告「净增 / 无采样基线」供参考（不设门禁：该比值恒远大于 3%，因基线仅为
#      纯遍历下界，而真实 body 阶段主体开销为解密/透传，本基准不覆盖）。
#
# 用法：
#   pwsh scripts/bench-ttft.ps1                     # 默认 300ms/3 次
#   pwsh scripts/bench-ttft.ps1 -BenchTimeMs 1000 -Count 5
#
# 退出码：0 = 全部门禁通过；1 = 存在超预算项或基准缺失。

[CmdletBinding()]
param(
	[int]$BenchTimeMs = 300,
	[int]$Count = 3,
	[int]$LatencyBudgetUs = 20,
	[int]$StreamMsPerToken = 15,
	[double]$BodySampleBudgetPct = 3.0
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
	# 解析 go test -bench 输出：Benchmark 名 → 最小 ns/op。
	function Get-BenchTable {
		param([string[]]$Lines, [string]$Filter)
		$best = @{}
		foreach ($l in $Lines) {
			if ($l -match '^(Benchmark\S+)\s+\d+\s+([0-9.]+)\s+ns/op') {
				$name = ($Matches[1] -replace '-\d+$', '')
				$v = [double]$Matches[2]
				if ($name -match $Filter) {
					if (-not $best.ContainsKey($name) -or $v -lt $best[$name]) { $best[$name] = $v }
				}
			}
		}
		return $best
	}

	$fail = @()

	Write-Output '=== P1-6 M6.4 性能基准 ==='
	Write-Output ("[参数] benchtime={0}ms count={1} 选路预算<{2}us 采样预算<{3}%" -f $BenchTimeMs, $Count, $LatencyBudgetUs, $BodySampleBudgetPct)

	# ---- 1) 选路基准 ----
	Write-Output ''
	Write-Output ("[选路] 预算 < {0} us/op" -f $LatencyBudgetUs)
	$reOut = @(& go test -run '^$' `
			-bench 'BenchmarkPickEndpoint_(LatencyAware|LatencyFastest|Hybrid)' `
			-benchmem -benchtime "${BenchTimeMs}ms" -count $Count `
			./gateway/wasm/otpmask-plugin/routeengine/ 2>&1 | ForEach-Object { "$_" })
	if ($LASTEXITCODE -ne 0) { $fail += "选路基准执行失败（go test exit=$LASTEXITCODE）" }
	$latency = Get-BenchTable -Lines $reOut -Filter '^BenchmarkPickEndpoint_(LatencyAware|LatencyFastest|Hybrid)'
	if ($latency.Count -eq 0) { $fail += '未解析到选路基准结果' }
	foreach ($k in ($latency.Keys | Sort-Object)) {
		$us = $latency[$k] / 1000.0
		$ok = $us -lt $LatencyBudgetUs
		if (-not $ok) { $fail += ("选路超预算：{0} = {1:N2} us/op (>= {2})" -f $k, $us, $LatencyBudgetUs) }
		Write-Output ("  {0,-42} {1,8:N2} us/op  {2}" -f $k, $us, $(if ($ok) { 'OK' } else { 'FAIL' }))
	}
	# 非延迟策略基线（对比用；不设门禁）
	$baseOut = @(& go test -run '^$' -bench 'BenchmarkPickEndpoint_100Weighted$' `
			-benchmem -benchtime "${BenchTimeMs}ms" -count $Count `
			./gateway/wasm/otpmask-plugin/routeengine/ 2>&1 | ForEach-Object { "$_" })
	$base = Get-BenchTable -Lines $baseOut -Filter '^BenchmarkPickEndpoint_100Weighted$'
	if ($base.Count -gt 0) {
		foreach ($k in $base.Keys) {
			Write-Output ("  [基线] {0,-34} {1,8:N2} us/op" -f $k, ($base[$k] / 1000.0))
		}
	}

	# ---- 2) body 采样基准 ----
	Write-Output ''
	Write-Output ("[body 采样] 参考 1k token 流式响应（{0}ms/token → {1}ms）" -f $StreamMsPerToken, (1000 * $StreamMsPerToken))
	$spOut = @(& go test -run '^$' -bench 'BenchmarkBody\w+_1kTokens' `
			-benchmem -benchtime "${BenchTimeMs}ms" -count $Count `
			./gateway/wasm/otpmask-plugin/streamparser/ 2>&1 | ForEach-Object { "$_" })
	if ($LASTEXITCODE -ne 0) { $fail += "body 采样基准执行失败（go test exit=$LASTEXITCODE）" }
	$body = Get-BenchTable -Lines $spOut -Filter '^BenchmarkBody\w+_1kTokens$'
	$sample = $null; $forward = $null; $upper = $null
	foreach ($k in $body.Keys) {
		switch ($k) {
			'BenchmarkBodySample_1kTokens' { $sample = $body[$k] }
			'BenchmarkBodySampleNoEarlyExit_1kTokens' { $upper = $body[$k] }
			'BenchmarkBodyForward_1kTokens' { $forward = $body[$k] }
		}
	}
	if ($null -eq $sample) { $fail += '未解析到 BenchmarkBodySample_1kTokens' }
	if ($null -eq $upper) { $fail += '未解析到 BenchmarkBodySampleNoEarlyExit_1kTokens' }
	if ($null -eq $forward) { $fail += '未解析到 BenchmarkBodyForward_1kTokens' }
	if ($null -ne $sample -and $null -ne $upper -and $null -ne $forward) {
		$refStreamNs = 1000.0 * $StreamMsPerToken * 1e6
		# 门禁以**上界**（逐帧全量判定，无早返回）为准，保守且非平凡。
		$pctUpper = 100.0 * $upper / $refStreamNs
		$ok = $pctUpper -lt $BodySampleBudgetPct
		if (-not $ok) { $fail += ("body 采样上界超预算：{0:N6}% (>= {1}%)" -f $pctUpper, $BodySampleBudgetPct) }
		# 真实路径净增（首 token 早返回）与透传基线对比。
		$netRaw = $sample - $forward
		$netAdded = [Math]::Max($netRaw, 0)
		$pctReal = 100.0 * $netAdded / $refStreamNs
		Write-Output ("  {0,-42} {1,8:N2} us/op" -f 'BenchmarkBodySample_1kTokens（真实·早返回）', ($sample / 1000.0))
		Write-Output ("  {0,-42} {1,8:N2} us/op" -f 'BenchmarkBodySampleNoEarlyExit_1kTokens（上界）', ($upper / 1000.0))
		Write-Output ("  {0,-42} {1,8:N2} us/op" -f 'BenchmarkBodyForward_1kTokens（透传基线）', ($forward / 1000.0))
		Write-Output ("  真实净增 {0:N2} us/op（原始差 {1:N2}）；占参考流时长 = {2:N6}%" -f ($netAdded / 1000.0), ($netRaw / 1000.0), $pctReal)
		Write-Output ("  上界占参考流时长 = {0:N6}%  {1}（门禁以此为准）" -f $pctUpper, $(if ($ok) { 'OK' } else { 'FAIL' }))
		if ($netRaw -le 0) {
			Write-Output '  [注] 真实采样路径全程 ≤ 透传基线（首 token 命中后早返回，R2-05），净增按 0 计'
		}
	}

	# ---- 汇总 ----
	Write-Output ''
	if ($fail.Count -gt 0) {
		Write-Output '=== 结果：FAIL ==='
		foreach ($f in $fail) { Write-Output ("  - {0}" -f $f) }
		exit 1
	}
	Write-Output '=== 结果：PASS（全部门禁通过）==='
}
finally {
	Pop-Location
}
