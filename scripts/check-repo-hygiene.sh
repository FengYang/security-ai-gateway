#!/usr/bin/env bash
# scripts/check-repo-hygiene.sh —— P2-4 仓库卫生自检（**防复发门禁**）
#
# 目的：把本轮两次「跨平台 / 构建口径」类踩坑固化成**可自动判定**的门禁，
#       避免同类问题再次只能靠人肉发现：
#         ① 构建三连红（docs 留证工件被当源码编译 → CI 红）；
#         ② shell 脚本缺执行位（100644 → 不可直接执行）。
#
# 【只读检查】本脚本**不修改任何文件**，只读工作树与 git 索引。
#
# 【退出码语义】
#   0 = 全部**适用**检查通过（SKIP/N-A 项会在报告中显式列出）
#   1 = 存在 FAIL 项（逐项列出失败文件与判定依据）
#   2 = **环境不满足，无法判定**（缺 git / 缺 go / 显式 --skip-build）
#       → 此时**不冒充通过**：不得把退出码 2 当作门禁放行
#
# 【用法】
#   scripts/check-repo-hygiene.sh                 # 全量检查
#   scripts/check-repo-hygiene.sh --skip-build    # 跳过 C1 构建三连（快速体检）
#   scripts/check-repo-hygiene.sh --docs-repo /path/to/docs   # 显式指定 docs 库检出
#   scripts/check-repo-hygiene.sh --gofmt-dir gateway/gateway-core/   # 追加 gofmt 检查域
#
# 【兼容】Windows Git Bash 与 Linux 均可运行（仅用 POSIX 常用工具 + git/go）。
#        Windows 工作树因 core.autocrlf 为 CRLF，故 gofmt 检查做 **CRLF 归一化** 比较，
#        避免把「仅换行符差异」误判为格式漂移。

set -u
LC_ALL=C
export LC_ALL

SCRIPT_NAME="$(basename "$0")"
FAIL_COUNT=0
SKIP_COUNT=0
NA_COUNT=0
BLOCKERS=""

# ---------------------------------------------------------------- 输出helpers
say()  { printf '%s\n' "$*"; }
rule() { printf -- '---------------------------------------------------------------\n'; }

section() {
  rule
  say "[$1] $2"
  rule
}

verdict_pass() { say "  判定: PASS —— $1"; }
verdict_fail() { say "  判定: FAIL —— $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
verdict_skip() { say "  判定: SKIP（无法判定）—— $1"; SKIP_COUNT=$((SKIP_COUNT + 1)); }
verdict_na()   { say "  判定: N/A（本次不适用）—— $1"; NA_COUNT=$((NA_COUNT + 1)); }

# 打印命令原文与（截断的）实际输出，便于 CI 日志定位
show_cmd() { say "  命令: $*"; }
show_out() {
  # $1=标题 $2=输出内容（可能为空）
  if [ -z "${2:-}" ]; then
    say "  输出: （无）"
  else
    say "  输出（前 20 行）:"
    printf '%s\n' "$2" | head -20 | sed 's/^/    | /'
    local n
    n="$(printf '%s\n' "$2" | wc -l | tr -d ' ')"
    [ "$n" -gt 20 ] && say "    | …（共 $n 行，已截断）"
  fi
}

# ---------------------------------------------------------------- 参数解析
SKIP_BUILD=0
DOCS_REPO=""
GOFMT_DIRS="gateway/gateway-core/ gateway/gateway-admin-service/"

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1; shift ;;
    --docs-repo)  DOCS_REPO="${2:-}"; shift 2 ;;
    --gofmt-dir)  GOFTM_DIR_EXTRA="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) say "未知参数: $1（用 --help 查看用法）"; exit 2 ;;
  esac
done
[ -n "${GOFTM_DIR_EXTRA:-}" ] && GOFTMT_DIRS="$GOFMT_DIRS $GOFTM_DIR_EXTRA"

# ---------------------------------------------------------------- 定位仓库根
if ! command -v git >/dev/null 2>&1; then
  say "环境不满足：本机没有 git（无法判定仓库卫生）→ 退出码 2"
  exit 2
fi
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$ROOT" ]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  if ! git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    say "环境不满足：既不在 git 仓库内、也未找到仓库根（当前目录: $(pwd)）→ 退出码 2"
    exit 2
  fi
fi
cd "$ROOT" || { say "环境不满足：无法进入仓库根 $ROOT → 退出码 2"; exit 2; }

say "==============================================================="
say "$SCRIPT_NAME —— P2-4 仓库卫生自检"
say "仓库根: $ROOT"
say "HEAD:   $(git rev-parse --short HEAD 2>/dev/null || echo 未知)"
say "模式:   $([ "$SKIP_BUILD" -eq 1 ] && echo '跳过 C1 构建三连（--skip-build）' || echo '全量检查')"
say "==============================================================="

# ---------------------------------------------------------------- 定位 docs 库（独立 git 库）
DOCS_DIR=""
if [ -n "$DOCS_REPO" ]; then
  [ -d "$DOCS_REPO" ] && DOCS_DIR="$(cd "$DOCS_REPO" && pwd)"
elif [ -d "docs/.git" ]; then
  DOCS_DIR="$(cd docs && pwd)"
fi

# ================================================================ C1 构建三连
section "C1" "构建三连（CI 同款：go build / go vet / go test 编译校验）"
if [ "$SKIP_BUILD" -eq 1 ]; then
  verdict_skip "显式 --skip-build：构建三连未执行 → 本次**不能**作为全量门禁依据（退出码 2）"
  BLOCKERS="$BLOCKERS 构建三连(--skip-build)"
elif ! command -v go >/dev/null 2>&1; then
  verdict_skip "本机没有 go（无法执行构建三连）→ 退出码 2"
  BLOCKERS="$BLOCKERS 缺go"
else
  GOVER="$(go env GOVERSION 2>/dev/null || echo 未知)"
  say "  go 版本: $GOVER"
  # 工具链版本门槛：低于 go.mod 要求时**无法判定**（是环境问题，不是仓库卫生问题）
  GOMOD_VER="$(awk '/^go [0-9]/{print $2; exit}' go.mod 2>/dev/null || true)"
  GO_LOCAL="$(printf '%s' "$GOVER" | sed 's/^go//')"
  TOO_OLD=0
  if [ -n "$GOMOD_VER" ] && [ -n "$GO_LOCAL" ]; then
    lo_major="${GO_LOCAL%%.*}"; lo_rest="${GO_LOCAL#*.}"; lo_minor="${lo_rest%%.*}"
    mo_major="${GOMOD_VER%%.*}"; mo_rest="${GOMOD_VER#*.}"; mo_minor="${mo_rest%%.*}"
    if [ "$lo_major" -lt "$mo_major" ] 2>/dev/null ||
       { [ "$lo_major" -eq "$mo_major" ] && [ "$lo_minor" -lt "$mo_minor" ]; } 2>/dev/null; then
      TOO_OLD=1
    fi
  fi
  if [ "$TOO_OLD" -eq 1 ]; then
    verdict_skip "本机 Go 版本 $GO_LOCAL 低于 go.mod 要求 $GOMOD_VER → 构建三连无法判定（环境不满足）→ 退出码 2"
    BLOCKERS="$BLOCKERS Go版本过低($GO_LOCAL<$GOMOD_VER)"
  else
  c1_fail=0
  for step in build vet test; do
    case "$step" in
      build) cmd="go build ./..." ;;
      vet)   cmd="go vet ./..." ;;
      test)  cmd="go test -run NoSuchTestPattern__repo_hygiene_probe__ ./..." ;;
    esac
    show_cmd "$cmd"
    out="$(eval "$cmd" 2>&1)"
    rc=$?
    show_out "$step" "$out"
    if [ $rc -eq 0 ]; then
      say "  结果: $step → 退出码 0"
    else
      say "  结果: $step → 退出码 $rc"
      c1_fail=$((c1_fail + 1))
    fi
  done
  if [ "$c1_fail" -eq 0 ]; then
    verdict_pass "构建三连全绿（build / vet / test 编译校验均退出码 0）"
  else
    verdict_fail "构建三连有 $c1_fail 步失败（详见上方命令与输出）"
  fi
  fi
fi

# ================================================================ C2 shell 执行位
section "C2" "shell 脚本执行位（scripts/**.sh 必须为 100755）"
show_cmd "git ls-files -s scripts/  → 筛出 mode=100644 且路径以 .sh 结尾"
bad_sh=""
while IFS=$'\t' read -r meta path; do
  [ -z "${path:-}" ] && continue
  mode="${meta%% *}"
  case "$path" in
    *.sh) [ "$mode" = "100644" ] && bad_sh="$bad_sh$path
" ;;
  esac
done < <(git ls-files -s scripts/ 2>/dev/null)

if [ -z "$bad_sh" ]; then
  verdict_pass "scripts/ 下所有 .sh 均为 100755（可执行位齐备）"
else
  show_out "C2" "$(printf '%s' "$bad_sh" | head -20)"
  verdict_fail "以下 .sh 缺执行位（mode=100644），须 git add --chmod=+x：$(printf '%s' "$bad_sh" | tr '\n' ' ')"
fi

# ================================================================ C3 留证工件排除口径
section "C3" "留证工件排除口径（docs/verify/crypto/p2-3/*/artifacts/*.go 必须全部带 //go:build ignore）"
if [ -z "$DOCS_DIR" ]; then
  verdict_na "本次检出不含 docs 库（docs 为独立 git 库，主库检出不含 verify/ 留证）→ 未执行（用 --docs-repo 指定可覆盖）"
else
  show_cmd "grep -l '^//go:build ignore' <artifacts/*.go>  ⇔  与磁盘工件清单比对"
  miss=""
  total=0
  for f in "$DOCS_DIR"/verify/crypto/p2-3/*/artifacts/*.go; do
    [ -f "$f" ] || continue
    total=$((total + 1))
    first="$(head -1 "$f" 2>/dev/null || true)"
    case "$first" in
      *"//go:build ignore"*) : ;;
      *) miss="$miss$(basename "$(dirname "$f")")/$(basename "$f")
" ;;
    esac
  done
  say "  工件 .go 总数: $total"
  if [ "$total" -eq 0 ]; then
    verdict_na "docs 库中未找到 artifacts/*.go（口径不适用）"
  elif [ -z "$miss" ]; then
    verdict_pass "全部 $total 个工件均带 //go:build ignore（不参与构建 → CI 不会因工件复红）"
  else
    show_out "C3" "$(printf '%s' "$miss" | head -20)"
    verdict_fail "以下工件缺 //go:build ignore（会被纳入构建 → CI 复红）：$(printf '%s' "$miss" | tr '\n' ' ')"
  fi
fi

# ================================================================ C4 gofmt 干净度
section "C4" "gofmt 干净度（CRLF 归一化比较；已知漂移走 baseline，新增漂移即 FAIL）"
BASELINE="scripts/check-repo-hygiene.gofmt-baseline.txt"
if ! command -v gofmt >/dev/null 2>&1; then
  verdict_skip "本机没有 gofmt（无法判定）→ 退出码 2"
  BLOCKERS="$BLOCKERS 缺gofmt"
else
  show_cmd "gofmt -l $GOFMT_DIRS  →  再用 CRLF 归一化 diff 过滤假阳性"
  drift=""
  for d in $GOFMT_DIRS; do
    [ -d "$d" ] || continue
    for f in $(gofmt -l "$d" 2>/dev/null); do
      # 两侧**对称剥离 CR** 后比较：gofmt 会保留源文件的换行符（CRLF 输入 → CRLF 输出），
      # 故必须两边都归一化，否则「仅换行符差异」会被误判为格式漂移（Windows 假阳性）。
      if ! diff -q <(gofmt "$f" 2>/dev/null | tr -d '\r') <(tr -d '\r' < "$f") >/dev/null 2>&1; then
        # 路径分隔符归一化为正斜杠（Windows gofmt -l 输出反斜杠），与 baseline 一致
        drift="$drift${f//\\//}
"
      fi
    done
  done
  known=""
  new=""
  while IFS= read -r line; do
    line="${line%$'\r'}"   # 去尾部 CR（baseline 文件可能是 CRLF，避免匹配失败）
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    if printf '%s' "$drift" | grep -Fxq "$line"; then
      known="$known$line
"
    else
      new="$new$line
"
    fi
  done < "$BASELINE" 2>/dev/null || true
  if [ -z "$drift" ]; then
    verdict_pass "检查域内无格式漂移：$GOFMT_DIRS"
  elif [ -z "$new" ]; then
    show_out "C4" "$(printf '%s' "$known" | head -20)"
    verdict_pass "仅存在**已知漂移**（baseline 内，无新增）：$(printf '%s' "$known" | tr '\n' ' ')"
    say "  提示: 已知漂移需由各自域责任人清理；baseline 不得自动扩充（否则会掩盖新增漂移）"
  else
    show_out "C4" "$(printf '%s' "$new" | head -20)"
    verdict_fail "存在**新增**格式漂移（不在 baseline）：$(printf '%s' "$new" | tr '\n' ' ')"
    [ -n "$known" ] && say "  另有已知漂移（baseline 内，不计 FAIL）：$(printf '%s' "$known" | tr '\n' ' ')"
  fi
fi

# ================================================================ C5 临时产物未被跟踪
section "C5" "临时产物未被跟踪（sag-*.tgz / tmp_* / .probe_tmp/）"
show_cmd "git ls-files | grep -E '^(sag-.*\.tgz|tmp_|\.probe_tmp/)'"
hit="$(git ls-files 2>/dev/null | grep -E '^(sag-.*\.tgz|tmp_|\.probe_tmp/)' || true)"
if [ -z "$hit" ]; then
  verdict_pass "无临时产物被跟踪（.gitignore 覆盖生效）"
else
  show_out "C5" "$hit"
  verdict_fail "以下临时产物被跟踪（须从索引移除）：$(printf '%s' "$hit" | tr '\n' ' ')"
fi

# ================================================================ C6 docs 工件未被误提交
section "C6" "docs 工件未被误提交（工件只应作为留证存在于 docs 库，不得进入主库）"
show_cmd "git ls-files | grep -E '^docs/verify/crypto/p2-3/'   （主库侧）"
main_hit="$(git ls-files 2>/dev/null | grep -E '^docs/verify/crypto/p2-3/' || true)"
c6_ok=1
if [ -n "$main_hit" ]; then
  show_out "C6-主库" "$main_hit"
  verdict_fail "主库跟踪了 docs/verify/crypto/p2-3 下的文件（应属 docs 独立库）"
  c6_ok=0
fi
if [ -z "$DOCS_DIR" ]; then
  verdict_na "docs 库不在本次检出内 → 未做登记一致性核对"
elif [ "$c6_ok" -eq 1 ]; then
  show_cmd "git -C <docs> ls-files 'verify/crypto/p2-3/*/artifacts/*'  ⇔ 磁盘工件清单"
  disk=0
  for f in "$DOCS_DIR"/verify/crypto/p2-3/*/artifacts/*; do
    [ -f "$f" ] && disk=$((disk + 1))
  done
  tracked="$(git -C "$DOCS_DIR" ls-files 'verify/crypto/p2-3/*/artifacts/*' 2>/dev/null | wc -l | tr -d ' ')"
  say "  磁盘工件文件数: $disk ；docs 库已登记: $tracked"
  if [ "$disk" != "$tracked" ]; then
    verdict_fail "工件登记与磁盘不一致（磁盘 $disk / 已登记 $tracked）→ 存在漏登记或误提交"
  else
    verdict_pass "工件仅作为留证存在于 docs 库，登记数与磁盘一致（$tracked），主库未跟踪"
  fi
fi

# ---------------------------------------------------------------- 汇总
rule
say "汇总: FAIL=$FAIL_COUNT  SKIP(无法判定)=$SKIP_COUNT  N/A(不适用)=$NA_COUNT"
if [ -n "$BLOCKERS" ]; then
  say "环境不满足项:$BLOCKERS"
fi
rule
if [ "$FAIL_COUNT" -gt 0 ]; then
  say "结论: ❌ 存在 $FAIL_COUNT 项 FAIL —— 不得作为门禁放行"
  exit 1
fi
if [ "$SKIP_COUNT" -gt 0 ]; then
  say "结论: ⚠️ 有 $SKIP_COUNT 项无法判定（环境不满足）—— **不冒充通过**，退出码 2"
  exit 2
fi
say "结论: ✅ 全部适用检查通过"
exit 0
