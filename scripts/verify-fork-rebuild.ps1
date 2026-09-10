# verify-fork-rebuild.ps1 - 本地 clean-room 校验：上游纯净克隆 + 定制补丁 = 可编译/可测试/可构建
#
# 存在理由（= .github/workflows/admin-portal.yml 的本地等价物）：
#   fork 目录 vendor/higress-console 不入库，入库的唯一交付物是补丁
#   fork-patches/higress-console/higress-console-custom.patch；因此必须证明
#   "上游纯净基线 + 补丁"可重建，防三类漂移：
#     ① 补丁不可应用（上游升级/rebase 后 conflict）；
#     ② 补丁不全（本地工作区有未纳入补丁的散改，本地能编、干净重建编不过）；
#     ③ 定制未编入产物（菜单注册点失效 → 页面 chunk 消失）。
#   与远端 CI 的差异：① 本机执行、不依赖 GitHub runner（本仓库暂无 remote，CI 无法触发）；
#   ② 后端增加 mvn test（CI 只 compile，抓不到测试期望漂移，如上游 #761 导致的 2 例
#   expected 2.0.0 / actual 2.0.1）。
#
# 流程：
#   1. 纯净克隆上游 v2.2.4（=baseline 36aa9c6）到 ASCII 临时目录
#      （仓库路径含中文"方案"，webpack 会拒绝 not-in-cwd 资源，无法就地构建）
#   2. git apply 定制补丁 + 打印落地文件清单
#   3. 后端：mvnw -pl console -am compile 与 test（skip npm/npx/pmd/checkstyle/delombok）
#   4. 前端：npm ci + npm run build（用 fork 内置 node16 运行时；CI 用 actions setup-node 16）
#   5. 断言产物含 index.html / security-center.html / p_security-center chunk
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts\verify-fork-rebuild.ps1 [-WorkDir <abs>]
# 退出码：0 = 全部通过；1 = 失败。
#
# 注：本脚本为 UTF-8 with BOM（含中文，PS 5.1 若按 ANSI 解析会破坏语法）。
# 注：工作目录每次运行都重新克隆（clean-room 语义，与 CI 的一次性 runner 对齐）；
#     目录保留以便失败排查，需要清理时手动删除。

param(
    [string]$WorkDir = (Join-Path $env:TEMP 'fork-rebuild')
)

$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

function Step([string]$msg) {
    Write-Output ''
    Write-Output ('===== ' + $msg + ' =====')
}

# ---- 固定输入（相对本脚本定位，勿写死绝对路径）-----------------------------
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$patchFile = Join-Path $repo 'fork-patches\higress-console\higress-console-custom.patch'
$forkRoot = Join-Path $repo 'vendor\higress-console'
$nodeDir = Join-Path $forkRoot 'frontend\node'
$jdkHome = Join-Path $repo '.tools\jdk-17.0.20.1+1'
$upstreamUrl = 'https://github.com/higress-group/higress-console.git'
$baseTag = 'v2.2.4'
$baseRev = '36aa9c6'
$mvnSkips = @('-Dskip.npm=true', '-Dskip.npx=true', '-Dpmd.skip=true',
    '-Dcheckstyle.skip=true', '-Dlombok.delombok.skip=true')

Step '0. 前置检查'
foreach ($p in @($patchFile, $forkRoot, $jdkHome)) {
    if (-not (Test-Path $p)) { Fail "缺少前置资源: $p" }
}
if (-not (Test-Path (Join-Path $nodeDir 'npm.cmd'))) {
    Fail "未找到 fork 内置 node 运行时: $nodeDir（前端构建需要它；CI 用 setup-node 16）"
}
Write-Output "patch   = $patchFile"
Write-Output "fork    = $forkRoot"
Write-Output "jdk     = $jdkHome"
Write-Output "workdir = $WorkDir"

# ---- 1. 纯净克隆上游 -------------------------------------------------------
Step "1. 克隆上游 $baseTag（=$baseRev）到工作目录"
$cloneDir = Join-Path $WorkDir 'higress-console'
if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
git clone --depth 1 --branch $baseTag $upstreamUrl $cloneDir
if ($LASTEXITCODE -ne 0) { Fail "上游克隆失败（$upstreamUrl $baseTag）" }
$head = (git -C $cloneDir rev-parse HEAD).Trim()
if (-not $head.StartsWith($baseRev)) {
    Fail "上游基线漂移：HEAD=$head，期望前缀 $baseRev（若上游重打了 tag，需更新 baseline.txt 与补丁）"
}
Write-Output "HEAD = $head （与 baseline $baseRev 一致）"

# ---- 2. 应用定制补丁 -------------------------------------------------------
Step '2. 应用定制补丁'
git -C $cloneDir apply --verbose $patchFile
if ($LASTEXITCODE -ne 0) { Fail "补丁应用失败（补丁已随上游漂移，需重导）: $patchFile" }
Write-Output '--- 补丁落地清单 ---'
git -C $cloneDir status --short | ForEach-Object { Write-Output $_ }

# ---- 3. 后端：编译 + 单测 --------------------------------------------------
Step '3. 后端编译（console -am, JDK17）'
$env:JAVA_HOME = $jdkHome
$env:MAVEN_OPTS = '-Dhttp.keepAlive=false'
Push-Location (Join-Path $cloneDir 'backend')
try {
    $mvnw = Join-Path $cloneDir 'backend\mvnw.cmd'
    & $mvnw -q -pl console -am compile @mvnSkips
    if ($LASTEXITCODE -ne 0) { Fail 'mvn compile 失败' }
    Write-Output 'mvn compile OK'

    Step '3b. 后端单测（console -am，含 sdk）'
    & $mvnw -pl console -am test @mvnSkips
    if ($LASTEXITCODE -ne 0) { Fail 'mvn test 失败' }
} finally {
    Pop-Location
}

# ---- 4. 前端：npm ci + build ----------------------------------------------
Step '4. 前端构建（npm ci + npm run build，node16）'
$oldPath = $env:Path
try {
    $env:Path = "$nodeDir;$env:Path"
    $npm = Join-Path $nodeDir 'npm.cmd'
    Push-Location (Join-Path $cloneDir 'frontend')
    try {
        & $npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { Fail 'npm ci 失败' }
        & $npm run build
        if ($LASTEXITCODE -ne 0) { Fail 'npm run build 失败' }
    } finally {
        Pop-Location
    }
} finally {
    $env:Path = $oldPath
}

# ---- 5. 断言定制已编入产物 -------------------------------------------------
Step '5. 断言定制已编入产物'
$out = Join-Path $cloneDir 'frontend\build'
foreach ($f in @('index.html', 'security-center.html')) {
    if (-not (Test-Path (Join-Path $out $f))) { Fail "构建产物缺少 $f（$out）" }
    Write-Output "OK  $f"
}
$chunk = Get-ChildItem (Join-Path $out 'js') -Filter 'p_security-center-index-*.js' -ErrorAction SilentlyContinue
if (-not $chunk) { Fail "构建产物缺少 p_security-center-index chunk（定制页面未编入）" }
Write-Output "OK  $($chunk[0].Name)"

Write-Output ''
Write-Output 'PASS: fork 可从上游纯净重建（apply 补丁 → 后端编译+单测 → 前端 npm ci+build → chunk 断言）'
Write-Output "工作目录: $cloneDir"
exit 0
