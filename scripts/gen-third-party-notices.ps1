#Requires -Version 5.1
<#
  gen-third-party-notices.ps1 —— 生成/更新第三方依赖许可清单（THIRD-PARTY-NOTICES.txt）

  用途：满足第三方开源许可的归属与声明义务（Apache-2.0 需保留版权与许可声明；MIT 需保留版权与许可文本）。
  做法：读取 go 模块图，逐个从本地模块缓存取 LICENSE/COPYING 原文并自动判定许可类型；
        默认先执行 `go mod download all` 以确保各模块源码（含 LICENSE）已在缓存中。
  口径（如实）：自动判定，**未逐项人工核对**；判定依据为许可原文特征串；无法识别时列出原文首行供人工判断。
  退出码：0 = 全部模块已识别；1 = 存在未识别/未找到（清单仍会生成，但需人工补齐）。

  用法：
    powershell -ExecutionPolicy Bypass -File scripts/gen-third-party-notices.ps1
    powershell -ExecutionPolicy Bypass -File scripts/gen-third-party-notices.ps1 -SkipDownload
#>
param(
    [switch]$SkipDownload,
    [string]$OutFile = (Join-Path $PSScriptRoot '..\THIRD-PARTY-NOTICES.txt')
)

$ErrorActionPreference = 'Stop'

if (-not $SkipDownload) {
    Write-Output "== go mod download all（确保各模块 LICENSE 已入本地缓存） =="
    & go mod download all 2>&1 | Select-Object -First 5
    if ($LASTEXITCODE -ne 0) { Write-Output "⚠ go mod download 返回码 $LASTEXITCODE（继续扫描已缓存模块）" }
}

# 模块清单（含 indirect 标记）
$mods = & go list -mod=mod -m -f "{{.Path}}|{{.Version}}|{{if .Indirect}}indirect{{else}}direct{{end}}" all 2>$null |
    Where-Object { $_ -and $_.Trim() -ne '' }

$rows = New-Object System.Collections.Generic.List[object]
foreach ($m in $mods) {
    $p, $v, $kind = $m -split '\|'
    if ($p -eq 'security-ai-gateway') { continue }   # 本模块自身（其根许可属待决项）
    $dir = & go list -mod=mod -m -f "{{.Dir}}" $p 2>$null
    $lic = '未找到'; $firstLine = ''
    if ($dir -and (Test-Path $dir)) {
        $f = Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING)' } | Select-Object -First 1
        if ($f) {
            $all = Get-Content $f.FullName -ErrorAction SilentlyContinue
            $head = ($all | Select-Object -First 80) -join "`n"
            $firstLine = (($all | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1) -as [string])
            if ($head -match 'Apache License') { $lic = 'Apache-2.0' }
            elseif ($head -match 'MIT License|The MIT License|Permission is hereby granted, free of charge') { $lic = 'MIT' }
            elseif ($head -match 'Neither the name') { $lic = 'BSD-3-Clause' }
            elseif ($head -match 'Redistribution and use in source and binary forms') { $lic = 'BSD-2-Clause' }
            elseif ($head -match 'ISC License|Permission to use, copy, modify, and/or distribute') { $lic = 'ISC' }
            elseif ($head -match 'Mozilla Public License') { $lic = 'MPL-2.0' }
            elseif ($head -match 'Unlicense|This is free and unencumbered software') { $lic = 'Unlicense' }
            elseif ($head -match 'zlib License|altered source versions') { $lic = 'Zlib' }
            else { $lic = "未识别（$($f.Name)）" }
        }
    }
    $rows.Add([pscustomobject]@{ Path = $p; Version = $v; Kind = $kind; License = $lic; FirstLine = "$firstLine".Trim() })
}

$unresolved = @($rows | Where-Object { $_.License -like '未识别*' -or $_.License -eq '未找到' })

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('OTP-Mask 安全 AI 网关 — 第三方依赖许可清单（THIRD-PARTY NOTICES）')
[void]$sb.AppendLine('================================================================')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('用途：满足第三方开源许可的归属与声明义务（Apache-2.0 须保留版权与许可声明；MIT/BSD/ISC 须保留版权与许可文本）。')
[void]$sb.AppendLine('生成方式：scripts/gen-third-party-notices.ps1 读取 Go 模块图与本地模块缓存 LICENSE 原文自动判定；请勿手工编辑本文件。')
[void]$sb.AppendLine('重新生成：powershell -ExecutionPolicy Bypass -File scripts/gen-third-party-notices.ps1')
[void]$sb.AppendLine("生成时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('如实说明（避免把自动扫描当合规结论）：')
[void]$sb.AppendLine('  1. 本清单为**自动判定**结果，未逐项人工核对；完整许可全文随各依赖模块分发（go mod download 可取得）。')
[void]$sb.AppendLine('  2. 判定依据为 LICENSE/COPYING 原文特征串；「未识别/未找到」项会在下方单列并附原文首行，须人工确认。')
[void]$sb.AppendLine('  3. 本项目自身尚未声明根许可（仓库无 LICENSE 文件），属待决项；不影响本清单对第三方许可的归属义务。')
[void]$sb.AppendLine('  4. 依赖变更（增删/升级）后须重新生成并复核。')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('许可类型汇总：' + (($rows | Group-Object License | Sort-Object Count -Descending |
    ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' ｜ '))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| 模块 | 版本 | 类型 | 许可 |')
[void]$sb.AppendLine('| --- | --- | --- | --- |')
foreach ($r in ($rows | Sort-Object Kind, Path)) {
    [void]$sb.AppendLine("| $($r.Path) | $($r.Version) | $($r.Kind) | $($r.License) |")
}
[void]$sb.AppendLine('')
if ($unresolved.Count -gt 0) {
    [void]$sb.AppendLine('未识别/未找到（须人工确认；附许可原文首行）：')
    foreach ($u in $unresolved) { [void]$sb.AppendLine("  - $($u.Path)（$($u.License)）原文首行：$($u.FirstLine)") }
    [void]$sb.AppendLine('')
}
[void]$sb.AppendLine('待引入（国密化 S1，依据 docs/GA-国密库选型与许可审查.md）：')
[void]$sb.AppendLine('  模块：github.com/emmansun/gmsm（固定 >= v0.44.1）｜许可：MIT')
[void]$sb.AppendLine('  引入后须重新生成本清单，并确认 SM9 相关安全公告不影响 SM2/SM3/SM4 用途。')

$out = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path (Get-Location) $OutFile }
[System.IO.File]::WriteAllText($out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Output "== 第三方许可清单已生成 =="
Write-Output "  产出：$out（$((Get-Item $out).Length) 字节 / $($rows.Count) 模块）"
Write-Output ('  许可汇总：' + (($rows | Group-Object License | Sort-Object Count -Descending |
    ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' ｜ '))
if ($unresolved.Count -gt 0) {
    Write-Output "  ⚠ 未识别/未找到 $($unresolved.Count) 项（须人工确认）"
    exit 1
}
Write-Output '  校验：全部模块许可已识别'
exit 0
