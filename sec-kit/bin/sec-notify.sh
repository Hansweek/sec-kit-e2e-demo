#!/usr/bin/env bash
# ============================================================================
#  统一安全扫描结果通知 (sec-notify.sh) v2 · SAST+SCA 聚合卡片 · CI 平台无关
# ----------------------------------------------------------------------------
#  定位: 流水线最后一步调用。读取 sec-results/ 下各扫描脚本落盘的结果 JSON，
#        聚合成【一张卡片】推送到钉钉/企微/飞书群机器人。
#  卡片设计(让人不点链接也能看懂80%):
#        顶部总结论(✅通过/⛔阻断) → SAST 四色缺陷统计+TOP高危缺陷定位
#        → SCA 组件/漏洞统计+质量红线 → SBOM/VEX 产物 → 报告直达链接
#  报告获取方式(钉钉机器人无法直传文件, 采用三级链接):
#        ① SCA 免登录结果页(点开即看)  ② SAST 平台详情页(登录态)
#        ③ CI 产物包(PDF详情报告/全路径HTML/SPDX/VEX/Excel 全在)
#  输入:
#    RESULT_DIR   结果目录(默认 ./sec-results)，消费:
#      codeai-result.json         灵脉CodeAI SAST 结果
#      sast-defects-full.json     全缺陷+跟踪路径(TOP缺陷展示用, 可缺省)
#      sca-result.json            SCA 依赖扫描结果(v2含组件/漏洞统计)
#      sca-result-artifact.json   SCA 制品扫描结果
#      sbom-info.json             SBOM/VEX 导出清单
#    NOTIFY_WEBHOOK/NOTIFY_TYPE/NOTIFY_SECRET/NOTIFY_AT  通知配置(与扫描脚本同变量名)
#    NOTIFY_TOP_N                 TOP缺陷条数(默认3, 0=不展示)
#    NOTIFY_AT_ON_FAIL=1          默认: 仅门禁阻断时@手机号(0=总是@)
#  退出码: 0=推送成功或未配置webhook  2=环境错误
# ============================================================================
set -uo pipefail
LOG_PREFIX="[NOTIFY]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }
die()  { echo "$LOG_PREFIX [错误] $*" >&2; exit 2; }

command -v curl >/dev/null 2>&1 || die "缺少 curl"
command -v jq   >/dev/null 2>&1 || die "sec-notify 需要 jq"

RESULT_DIR="${RESULT_DIR:-./sec-results}"
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
NOTIFY_TYPE="${NOTIFY_TYPE:-dingtalk}"
NOTIFY_SECRET="${NOTIFY_SECRET:-}"
NOTIFY_AT="${NOTIFY_AT:-}"
NOTIFY_AT_ON_FAIL="${NOTIFY_AT_ON_FAIL:-1}"
NOTIFY_TOP_N="${NOTIFY_TOP_N:-3}"
NOTIFY_TITLE_PREFIX="${NOTIFY_TITLE_PREFIX:-🛡️ 安全扫描}"
BUILD_URL="${BUILD_URL:-}"
REPO_LABEL="${REPO_LABEL:-}"                  # 卡片标题仓库名(缺省取应用名去分支后缀)
TLS_INSECURE="${TLS_INSECURE:-1}"
[ "$TLS_INSECURE" = "1" ] && TLS_FLAGS="-k" || TLS_FLAGS=""

urlencode() { printf '%s' "$1" | jq -sRr '@uri'; }

# ---- 读取结果文件 ----
rj() { if [ -f "$1" ]; then cat "$1"; else echo '{}'; fi; }
SAST=$(rj "$RESULT_DIR/codeai-result.json")
DFULL=$(rj "$RESULT_DIR/sast-defects-full.json")
SCA=$(rj "$RESULT_DIR/sca-result.json")
SCAA=$(rj "$RESULT_DIR/sca-result-artifact.json")
SBOM=$(rj "$RESULT_DIR/sbom-info.json")

has_any=0
verdict="✅ 通过"

# ================= SAST 段 =================
SAST_SEC=""
META_LINE=""
if [ "$(echo "$SAST" | jq -r '.appName // empty')" != "" ]; then
  has_any=1
  app=$(echo "$SAST" | jq -r '.appName')
  sup=$(echo  "$SAST" | jq -r '.defectCount.super // 0')
  high=$(echo "$SAST" | jq -r '.defectCount.high // 0')
  mid=$(echo  "$SAST" | jq -r '.defectCount.middle // 0')
  low=$(echo  "$SAST" | jq -r '.defectCount.low // 0')
  gate=$(echo "$SAST" | jq -r '.gateResult // "未启用"')
  mode=$(echo "$SAST" | jq -r '.scanMode // "全量扫描"')
  stime=$(echo "$SAST" | jq -r '.scanTime // empty')
  branch=$(echo "$SAST" | jq -r '.branch // empty')
  author=$(echo "$SAST" | jq -r '.author // empty')
  [ -z "$REPO_LABEL" ] && REPO_LABEL="${app%-*}"
  case "$gate" in
    *不通过*) sast_gate_line="⛔ **${gate}**"; verdict="⛔ 存在阻断项" ;;
    *放行*)   sast_gate_line="⏭ ${gate}" ;;
    *)        sast_gate_line="✅ ${gate}" ;;
  esac
  META_LINE="${mode}${branch:+ ｜ 分支 ${branch}}${author:+ ｜ ${author}}${stime:+ ｜ ${stime}}"
  SAST_SEC="**① 源码检测 · 灵脉CodeAI**

- 缺陷：🔴 超危 **${sup}**　🟠 高危 **${high}**　🟡 中危 **${mid}**　⚪ 低危 **${low}**
- 门禁：${sast_gate_line}"
  # TOP 高危缺陷(超危+高危前N条; 路径取最后两级避免刷屏)
  if [ "$NOTIFY_TOP_N" != "0" ] && [ "$(echo "$DFULL" | jq -r '.defects // [] | length' 2>/dev/null)" != "0" ]; then
    top_list=$(echo "$DFULL" | jq -r --argjson n "$NOTIFY_TOP_N" '
      [.defects[] | select(.riskLevel==1 or .riskLevel==2)] |
      sort_by(.riskLevel) | .[0:$n] |
      .[] | (.flawLocation // .fileName // "?") as $loc |
      ($loc | split("/") | .[-2:] | join("/")) as $short |
      "- " + (if .riskLevel==1 then "🔴" else "🟠" end) +
        " **" + (.defectName // .ruleName // "未知") + "** — " + $short + ":" + ((.startLine // "-")|tostring)' 2>/dev/null)
    if [ -n "$top_list" ]; then
      top_total=$(echo "$DFULL" | jq -r '[.defects[] | select(.riskLevel==1 or .riskLevel==2)] | length')
      SAST_SEC="${SAST_SEC}
- 高危 TOP${NOTIFY_TOP_N}（超/高危共 ${top_total} 条）：
${top_list}"
    fi
  fi
  sast_url=$(echo "$SAST" | jq -r '.reportUrl // empty')
  [ -n "$sast_url" ] && SAST_SEC="${SAST_SEC}
- [点此在平台查看缺陷详情与跟踪路径](${sast_url})"
fi

# ================= SCA 段 =================
SCA_SEC=""
sca_section() {  # sca_section <结果JSON> <标签> <序号>
  local J="$1" label="$2" idx="$3" app gate url line stat_line
  [ "$(echo "$J" | jq -r '.appName // empty' 2>/dev/null)" != "" ] || return 0
  has_any=1
  app=$(echo "$J" | jq -r '.appName')
  gate=$(echo "$J" | jq -r '.gate // "未启用"')
  url=$(echo  "$J" | jq -r '.resultUrl // ""')
  [ -z "$REPO_LABEL" ] && REPO_LABEL="${app%-*}"
  case "$gate" in
    *⛔*|*不通过*) line="⛔ **${gate}**"; verdict="⛔ 存在阻断项" ;;
    *放行*|*未启用*) line="ℹ️ ${gate}" ;;
    *) line="✅ ${gate}" ;;
  esac
  stat_line=""
  if [ "$(echo "$J" | jq -r '.vulNum // empty' 2>/dev/null)" != "" ]; then
    stat_line="- 组件 **$(echo "$J" | jq -r '.componentNum')** 个，漏洞 **$(echo "$J" | jq -r '.vulNum')** 个（严重 $(echo "$J" | jq -r '.vulSeriousNum // 0') / 高 $(echo "$J" | jq -r '.vulHighNum // 0') / 中 $(echo "$J" | jq -r '.vulMediumNum // 0') / 低 $(echo "$J" | jq -r '.vulLowNum // 0')）"
  fi
  SCA_SEC="${SCA_SEC}**${idx} 组件检测 · 源鉴SCA（${label}）**

- 质量红线：${line}
${stat_line}
- [点此查看完整检测报告（免登录）](${url})

"
}
sca_section "$SCA"  "依赖分析" "②"
sca_section "$SCAA" "制品成分" "③"

# ================= SBOM/VEX 段 =================
SBOM_SEC=""
if [ "$(echo "$SBOM" | jq -r '.files // [] | length' 2>/dev/null)" != "0" ]; then
  has_any=1
  sbom_counts=$(echo "$SBOM" | jq -r '.files | group_by(.desc) | .[] | "- \(.length) × \(.[0].desc)"' 2>/dev/null)
  SBOM_SEC="**④ SBOM / VEX 产物**（已随流水线归档）

${sbom_counts}"
fi

[ "$has_any" = "1" ] || { log "sec-results/ 下无扫描结果，跳过通知"; exit 0; }
[ -n "$NOTIFY_WEBHOOK" ] || { log "未配置 NOTIFY_WEBHOOK，跳过推送(结果见流水线日志与产物)"; exit 0; }

# ================= 拼装 =================
LINK_SEC="**⑤ 报告下载**"
[ -n "$BUILD_URL" ] && LINK_SEC="${LINK_SEC}

- [全套报告（PDF详情 / 缺陷全路径HTML / SBOM / VEX / Excel）](${BUILD_URL})"

TITLE="${NOTIFY_TITLE_PREFIX}｜${REPO_LABEL:-应用}"
META_LINE="${META_LINE:+ ｜ ${META_LINE}}"
BODY="## ${REPO_LABEL:-应用} · 安全扫描 ${verdict}

> **${verdict}**${META_LINE}


${SAST_SEC}


${SCA_SEC}${SBOM_SEC}


${LINK_SEC}"

# ---- @策略: 默认仅阻断时@NOTIFY_AT; NOTIFY_AT_ON_FAIL=0 时总是@ ----
at_now=0
[ "$verdict" = "⛔ 存在阻断项" ] && at_now=1
[ "${NOTIFY_AT_ON_FAIL}" = "0" ] && [ -n "$NOTIFY_AT" ] && at_now=1
AT_LINE=""
[ "$at_now" = "1" ] && [ -n "$NOTIFY_AT" ] && AT_LINE=" @${NOTIFY_AT//,/ @}"

# ---- 推送 ----
send_once() {
  local url="$NOTIFY_WEBHOOK" payload resp
  case "$NOTIFY_TYPE" in
    dingtalk)
      if [ -n "$NOTIFY_SECRET" ]; then
        local ts sign
        ts=$(date +%s000)
        sign=$(printf '%s\n%s' "$ts" "$NOTIFY_SECRET" \
               | openssl dgst -sha256 -hmac "$NOTIFY_SECRET" -binary | base64)
        url="${url}&timestamp=${ts}&sign=$(urlencode "$sign")"
      fi
      local at_mobiles="[]"
      [ "$at_now" = "1" ] && [ -n "$NOTIFY_AT" ] && at_mobiles=$(echo "$NOTIFY_AT" | jq -Rc 'split(",") | map(select(length>0))')
      payload=$(jq -n --arg t "$TITLE" --arg b "${BODY}${AT_LINE}" \
        --argjson ats "$at_mobiles" \
        '{msgtype:"markdown",markdown:{title:$t,text:$b},
          at:{atMobiles:$ats,isAtAll:false}}')
      ;;
    wecom)
      payload=$(jq -n --arg c "$BODY" '{msgtype:"markdown",markdown:{content:$c}}')
      ;;
    feishu)
      local plain
      plain=$(printf '%s' "$BODY" | sed -e 's/\*\*//g' -e 's/　/ /g' -e 's/^### //')
      payload=$(jq -n --arg t "★ ${TITLE} ${verdict}
${plain}" '{msg_type:"text",content:{text:$t}}')
      ;;
    *)
      warn "未知 NOTIFY_TYPE=$NOTIFY_TYPE，跳过推送"; return 0 ;;
  esac
  resp=$(curl -s $TLS_FLAGS --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$url")
  log "推送返回: $resp"
  echo "$resp" | grep -qiE '"errcode":0|"StatusCode":0|"code":0' && return 0
  return 1
}

if send_once; then
  log "聚合通知已推送"
else
  warn "首次推送未确认成功，5秒后重试一次..."
  sleep 5
  send_once || warn "推送仍未确认成功(不影响扫描结论；请检查机器人模式与关键词/加签配置)"
fi
exit 0
