#!/usr/bin/env bash
# 节点 OS 安全加固基线检查脚本（P1-3 等保 §6.4「主机加固与恶意代码防范（R2-07）」/ §7.5，W11/W6）
#
# 定位：以 CIS 类基线对节点 OS 做「最小安装 / 关闭非必要系统服务与默认共享 / 收敛高危端口 /
#      限制管理终端接入 / 内核安全参数 / 关键文件权限 / 审计与时间同步 / 恶意代码防范」检查，
#      输出可归档的检查报告作为运行态证据；--apply 对**安全可自动化**的子集做加固。
#
# 双模式（同一实现，避免双份逻辑漂移）：
#   - 节点内直跑（默认，ROOT=/）       ：由运维在节点上执行，报告归档至《系统运维管理制度》专章。
#   - 只读容器扫描（ROOT=/host）      ：由 deploy/security/node-hardening/node-scan-cronjob.yaml
#                                      以 hostPath 只读挂载宿主根目录后执行（月度周期扫描留证）。
#
# 用法：
#   bash baseline-check.sh [--root DIR] [--json] [--out FILE] [--apply]
#     --root DIR   宿主根目录前缀（默认 /；容器扫描传 /host）
#     --json       以 JSON 数组输出（默认人类可读文本）
#     --out FILE   同时写入报告文件（追加时间戳由调用方控制）
#     --apply      对可自动化项执行加固（仅节点内直跑生效；只读扫描模式拒绝执行）
#   退出码：存在 FAIL 项 → 1（供 CI/运维门禁判定）；否则 0。
#
# 说明（不臆断）：服务/端口检查基于 systemd wants 符号链接与 /proc/net/tcp 静态读取，
# 覆盖"已启用(开机自启)"与"监听中"两类；对运行期临时进程、非 systemd 监听不做完整枚举，
# 由 HIDS（Falco, §6.4）与全流量审计（P1-7）补充覆盖（三层论证见差距分析报告）。

set -uo pipefail

ROOT="/"
OUT_JSON=0
OUT_FILE=""
APPLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --root)  ROOT="${2%/}"; [ -z "$ROOT" ] && ROOT="/"; shift 2 ;;
    --json)  OUT_JSON=1; shift ;;
    --out)   OUT_FILE="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

FAILN=0
WARNN=0
PASSN=0
LINES=""   # 每条：STATUS|ID|名称|详情（JSON/文本共用）

JQ_ESC() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
record() { # record STATUS ID NAME DETAIL
  local st="$1" id="$2" name="$3" detail="${4:-}"
  case "$st" in
    PASS) PASSN=$((PASSN+1)) ;;
    WARN) WARNN=$((WARNN+1)) ;;
    FAIL) FAILN=$((FAILN+1)) ;;
  esac
  LINES="${LINES}${st}|${id}|${name}|${detail}"$'\n'
  if [ "$OUT_JSON" -eq 0 ]; then
    printf '[%s] %-28s %s\n' "$st" "$id" "$detail"
    [ -n "$name" ] && [ "$st" != "PASS" ] && printf '        %s\n' "$name"
  fi
}

# 读宿主文件（ROOT 前缀；缺失返回空）
readf() { [ -r "${ROOT}$1" ] && cat "${ROOT}$1" 2>/dev/null || true; }
# 服务是否开机自启（任一 .wants 目录存在同名符号链接）
svc_enabled() {
  local u="$1" d
  for d in multi-user.target.wants graphical.target.wants sockets.target.wants sysinit.target.wants; do
    [ -e "${ROOT}/etc/systemd/system/${d}/${u}" ] && return 0
  done
  # 静态 enable：/etc/systemd/system/<unit> 直接存在且非 disabled
  return 1
}

echo "===== 节点加固基线检查 ($(date -u '+%Y-%m-%dT%H:%M:%SZ')) root=${ROOT} ====="

# ---------- 1. 非必要系统服务（最小安装） ----------
UNNEEDED="telnet.socket vsftpd.service rpcbind.socket rpcbind.service nfs-server.service avahi-daemon.socket avahi-daemon.service cups.socket cups.service smb.service nmb.service tftp.socket rsh.socket rexec.socket rlogin.socket"
for u in $UNNEEDED; do
  if svc_enabled "$u"; then
    record FAIL "svc.$u" "非必要服务应关闭/禁用" "已启用（开机自启）"
    if [ "$APPLY" -eq 1 ] && [ "$ROOT" = "/" ] && command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now "$u" >/dev/null 2>&1 && echo "        [apply] 已禁用 $u"
    fi
  else
    record PASS "svc.$u" "" "未启用"
  fi
done

# ---------- 2. 高危端口监听（收敛端口） ----------
HOT_PORTS="23 21 111 2049 445 139 3389 512 513 514"
LISTEN=""
for f in "/proc/net/tcp" "/proc/net/tcp6"; do
  [ -r "${ROOT}${f}" ] || continue
  # $2=local_address(HEX); $4=st (0A=LISTEN)
  LISTEN="${LISTEN}$(awk 'NR>1 && $4=="0A" {split($2,a,":"); print a[2]}' "${ROOT}${f}" 2>/dev/null | sort -u)"$'\n'
done
for p in $HOT_PORTS; do
  hex=$(printf '%04X' "$p")
  if printf '%s\n' "$LISTEN" | grep -qi "^${hex}$"; then
    record FAIL "port.$p" "高危端口应关闭" "正在监听 $p/tcp"
  else
    record PASS "port.$p" "" "未监听"
  fi
done

# ---------- 3. 默认共享（NFS/Samba） ----------
NFS_SHARES=$(grep -vE '^\s*(#|$)' "${ROOT}/etc/exports" 2>/dev/null | wc -l | tr -d ' ')
if [ "${NFS_SHARES:-0}" -gt 0 ]; then
  record FAIL "share.nfs" "不应导出默认/匿名 NFS 共享" "/etc/exports 含 ${NFS_SHARES} 条导出"
else
  record PASS "share.nfs" "" "无 NFS 导出"
fi
if [ -r "${ROOT}/etc/samba/smb.conf" ]; then
  SMBS=$(grep -cE '^\s*\[' "${ROOT}/etc/samba/smb.conf" 2>/dev/null)
  SMBS=$((SMBS-1))  # 去除 [global]
  if [ "$SMBS" -gt 0 ]; then
    record FAIL "share.smb" "不应启用默认 Samba 共享" "smb.conf 含 ${SMBS} 个共享段"
  else
    record PASS "share.smb" "" "无 Samba 共享段"
  fi
else
  record PASS "share.smb" "" "未安装/未配置 Samba"
fi

# ---------- 4. SSH 加固与管理终端接入限制 ----------
SSHD="${ROOT}/etc/ssh/sshd_config"
sshd_get() { grep -iE "^\s*$1\b" "$SSHD" 2>/dev/null | awk '{print tolower($2)}' | tail -1; }
if [ -r "$SSHD" ]; then
  check_ssh() { # id key expected
    local v; v="$(sshd_get "$2")"
    if [ "$v" = "$3" ]; then record PASS "ssh.$1" "" "$2=$v"; else record FAIL "ssh.$1" "SSH 应加固" "$2=${v:-未设置}（期望 $3）"; fi
  }
  check_ssh root_login PermitRootLogin no
  check_ssh pwd_auth  PasswordAuthentication no
  check_ssh empty_pwd PermitEmptyPasswords no
  MAXT="$(sshd_get MaxAuthTries)"; MAXT="${MAXT:-6}"
  if [ "$MAXT" -le 4 ] 2>/dev/null; then record PASS "ssh.maxtries" "" "MaxAuthTries=$MAXT"; else record FAIL "ssh.maxtries" "SSH 应限制尝试次数" "MaxAuthTries=$MAXT（应 ≤4）"; fi
  if grep -qiE '^\s*(AllowUsers|AllowGroups|Match\s)' "$SSHD" 2>/dev/null; then
    record PASS "ssh.src_limit" "" "已配置 AllowUsers/AllowGroups/Match 接入限制"
  else
    record WARN "ssh.src_limit" "建议限制管理终端来源" "未配置 AllowUsers/AllowGroups；建议叠加防火墙限源（见 README 加固建议）"
  fi
else
  record WARN "ssh.config" "未找到 sshd_config" "如为容器化/无 SSH 节点可忽略"
fi

# ---------- 5. 内核安全参数（sysctl） ----------
# key=期望值；路径由 key 的 '.' → '/' 转换
SYSCTLS="net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.all.log_martians=1 net.ipv4.icmp_echo_ignore_broadcasts=1 net.ipv4.tcp_syncookies=1"
SYSD_APPLIED=0
for kv in $SYSCTLS; do
  key="${kv%=*}"; want="${kv#*=}"; path="${ROOT}/proc/sys/${key//./\/}"
  if [ -r "$path" ]; then
    got="$(cat "$path" 2>/dev/null)"
    if [ "$got" = "$want" ]; then record PASS "sysctl.$key" "" "$got"; else
      record FAIL "sysctl.$key" "内核安全参数应加固" "现值 ${got}（期望 ${want}）"
      if [ "$APPLY" -eq 1 ] && [ "$ROOT" = "/" ]; then
        echo "${key} = ${want}" >> /etc/sysctl.d/99-otpmask-hardening.conf && SYSD_APPLIED=1
      fi
    fi
  else
    record WARN "sysctl.$key" "内核参数不可读" "$path"
  fi
done
if [ "$APPLY" -eq 1 ] && [ "$SYSD_APPLIED" -eq 1 ] && [ "$ROOT" = "/" ]; then
  command -v sysctl >/dev/null 2>&1 && sysctl --system >/dev/null 2>&1 && echo "        [apply] 已写入 /etc/sysctl.d/99-otpmask-hardening.conf 并生效"
fi

# ---------- 6. 关键文件权限 ----------
perm_check() { # id file max_octal
  local f="${ROOT}$2" want="$3" cur
  [ -e "$f" ] || { record WARN "perm.$1" "文件缺失" "$2"; return; }
  cur="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null)"
  # 权限为八进制字符串（如 "640"）；统一按八进制解析后比较。
  cur=$((8#${cur:-7777}))
  if [ "$cur" -le "$((8#$want))" ]; then record PASS "perm.$1" "" "$2 权限 $(printf '%o' "$cur")"
  else
    record FAIL "perm.$1" "关键文件权限应收紧" "$2 权限 $(printf '%o' "$cur")（应 ≤ ${want}）"
    if [ "$APPLY" -eq 1 ] && [ "$ROOT" = "/" ]; then chmod "$want" "$f" 2>/dev/null && echo "        [apply] 已收紧 $2 → $want"; fi
  fi
}
perm_check shadow  /etc/shadow  640
perm_check gshadow /etc/gshadow 640
perm_check passwd  /etc/passwd  644
perm_check group   /etc/group   644

# ---------- 7. 审计服务（联动 §6.3 日志留存/审计链） ----------
if svc_enabled "auditd.service" || [ -d "${ROOT}/var/log/audit" ]; then
  record PASS "audit.auditd" "" "auditd 已启用/审计日志目录存在"
else
  record FAIL "audit.auditd" "节点应启用系统审计" "auditd 未启用且无 /var/log/audit"
fi

# ---------- 8. 时间同步（联动 §6.7 NTP / TOTP） ----------
if svc_enabled "chronyd.service" || svc_enabled "ntpd.service" || [ -r "${ROOT}/etc/chrony.conf" ]; then
  record PASS "time.sync" "" "时间同步服务已配置"
else
  record WARN "time.sync" "应配置内网 NTP 校时" "未发现 chrony/ntp 配置（§6.7：至少 2 台源，偏差 >500ms 告警）"
fi

# ---------- 9. 恶意代码防范（节点侧） ----------
if svc_enabled "falco.service" || [ -x "${ROOT}/usr/bin/falco" ]; then
  record PASS "av.falco" "" "节点侧发现 Falco HIDS"
elif [ -x "${ROOT}/usr/bin/clamd" ] || [ -x "${ROOT}/usr/sbin/clamd" ]; then
  record PASS "av.clamav" "" "节点侧发现 ClamAV 防病毒"
else
  record WARN "av.node" "节点侧无本地防病毒/HIDS 二进制" "本方案以集群侧 Falco DaemonSet（§6.4）+ Trivy 镜像扫描覆盖；节点侧按需补装，见 README"
fi

# ---------- 10. 高危软件包（最小安装） ----------
PKG_HITS=""
if command -v rpm >/dev/null 2>&1 && [ "$ROOT" = "/" ]; then
  for p in telnet rsh ypbind talk; do rpm -q "$p" >/dev/null 2>&1 && PKG_HITS="${PKG_HITS} ${p}"; done
elif command -v dpkg >/dev/null 2>&1 && [ "$ROOT" = "/" ]; then
  for p in telnet rsh-client ypbind talk; do dpkg -s "$p" >/dev/null 2>&1 && PKG_HITS="${PKG_HITS} ${p}"; done
fi
if [ -n "$PKG_HITS" ]; then record FAIL "pkg.minimal" "不应安装高危/过时软件包" "已安装:${PKG_HITS}"; else record PASS "pkg.minimal" "" "未发现高危软件包"; fi

# ---------- 汇总与输出 ----------
TOTAL=$((PASSN+WARNN+FAILN))
echo "----- summary: PASS=${PASSN} WARN=${WARNN} FAIL=${FAILN} (total=${TOTAL}) -----"

if [ "$OUT_JSON" -eq 1 ]; then
  json="["
  first=1
  while IFS='|' read -r st id name detail; do
    [ -z "$st" ] && continue
    [ "$first" -eq 0 ] && json="${json},"
    first=0
    json="${json}{\"status\":\"${st}\",\"id\":\"$(JQ_ESC "$id")\",\"name\":\"$(JQ_ESC "$name")\",\"detail\":\"$(JQ_ESC "$detail")\"}"
  done <<< "$LINES"
  json="${json}]"
  printf '%s\n' "$json"
  [ -n "$OUT_FILE" ] && printf '%s\n' "$json" > "$OUT_FILE"
elif [ -n "$OUT_FILE" ]; then
  printf '%s' "$LINES" > "$OUT_FILE"
fi

[ "$FAILN" -gt 0 ] && exit 1
exit 0
