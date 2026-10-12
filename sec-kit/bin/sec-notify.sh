#!/usr/bin/env bash
# ============================================================================
#  统一安全扫描结果通知 (sec-notify.sh) · SAST+SCA 聚合卡片 · CI 平台无关
# ----------------------------------------------------------------------------
#  定位: 流水线最后一步调用。读取 sec-results/ 下各扫描脚本落盘的结果 JSON，
#        聚合成【一张卡片】推送到钉钉/企微/飞书群机器人，替代"每个平台各自
#        配置通知"的分散方案——一次配置、消息聚合、可@人、可带CI链接。
#  输入:
#    RESULT_DIR   结果目录(默认 ./sec-results)，消费:
#      codeai-result.json         灵脉CodeAI SAST 结果(codeai-incremental-scan.sh 落盘)
#      sca-result.json            源鉴SCA 依赖扫描结果(sca-scan.sh deps 落盘)
#      sca-result-artifact.json   源鉴SCA 制品扫描结果(sca-scan.sh artifact 落盘)
#      sbom-info.json             SBOM/VEX 导出清单(sca-sbom.sh 落盘)
#    NOTIFY_WEBHOOK/NOTIFY_TYPE/NOTIFY_SECRET/NOTIFY_AT  通知配置(与扫描脚本同变量名)
#      NOTIFY_TYPE: dingtalk | wecom | feishu (钉钉支持加签 NOTIFY_SECRET)
#  用法(CI 末步):
#    bash sec-kit/bin/sec-notify.sh
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
NOTIFY_TITLE_PREFIX="${NOTIFY_TITLE_PREFIX:-🛡️ 安全扫描}"
BUILD_URL="${BUILD_URL:-}"
TLS_INSECURE="${TLS_INSECURE:-1}"
[ "$TLS_INSECURE" = "1" ] && TLS_FLAGS="-k" || TLS_FLAGS=""

urlencode() { printf '%s' "$1" | jq -sRr '@uri'; }

# ---- 读取各结果文件，聚合正文 ----
rj() { if [ -f "$1" ]; then cat "$1"; else echo '{}'; fi; }
SAST=$(rj "$RESULT_DIR/codeai-result.json")
SCA=$(rj "$RESULT_DIR/sca-result.json")
SCAA=$(rj "$RESULT_DIR/sca-result-artifact.json")
SBOM=$(rj "$RESULT_DIR/sbom-info.json")

has_any=0
SECTIONS=""

# SAST 段
if [ "$SAST" != "{}" ]; then
  has_any=1
  app=$(echo "$SAST" | jq -r '.appName // "N/A"')
  sup=$(echo  "$SAST" | jq -r '.defectCount.super // 0')
  high=$(echo "$SAST" | jq -r '.defectCount.high // 0')
  mid=$(echo  "$SAST" | jq -r '.defectCount.middle // 0')
  low=$(echo  "$SAST" | jq -r '.defectCount.low // 0')
  gate=$(echo "$SAST" | jq -r '.gateResult // "未启用"')
  mode=$(echo "$SAST" | jq -r '.scanMode // "全量扫描"')
  branch=$(echo "$SAST" | jq -r '.branch // ""')
  proj=$(echo "$SAST" | jq -r '.projectName // "快速检测"')
  case "$gate" in
    *⛔*|*✅*|*⏭*|*ℹ️*) gate_line="$gate" ;;
    *不通过*)        gate_line="⛔ ${gate}" ;;
    *放行*)          gate_line="⏭ ${gate}" ;;
    *)              gate_line="✅ ${gate}" ;;
  esac
  SECTIONS="${SECTIONS}**▪ 灵脉CodeAI(SAST)** 应用 \`${app}\` ${branch:+(分支 ${branch})}
　扫描方式: ${mode} | 项目: ${proj}
　缺陷: 超危 **${sup}** / 高危 **${high}** / 中危 **${mid}** / 低危 **${low}**
　门禁: ${gate_line}
"
fi

# SCA 段（依赖 + 制品）
sca_section() {  # sca_section <结果JSON> <标签>
  local J="$1" label="$2" app gate url gate_icon
  [ "$(echo "$J" | jq -r '.appName // empty' 2>/dev/null)" != "" ] || return 0
  has_any=1
  app=$(echo "$J" | jq -r '.appName')
  gate=$(echo "$J" | jq -r '.gate // "未启用"')
  url=$(echo  "$J" | jq -r '.resultUrl // ""')
  case "$gate" in
    *⛔*|*✅*|*ℹ️*) gate_line="$gate" ;;   # 文本已带图标
    *不通过*)        gate_line="⛔ ${gate}" ;;
    *放行*|*未启用*) gate_line="ℹ️ ${gate}" ;;
    *)              gate_line="✅ ${gate}" ;;
  esac
  SECTIONS="${SECTIONS}**▪ 源鉴SCA(${label})** 应用 \`${app}\`
　质量红线: ${gate_line}
　[查看检测详情](${url})
"
}
sca_section "$SCA"  "依赖组件"
sca_section "$SCAA" "制品成分"

# SBOM 段
if [ "$(echo "$SBOM" | jq -r '.files // [] | length')" != "0" ] 2>/dev/null; then
  has_any=1
  sbom_list=$(echo "$SBOM" | jq -r '.files[] | "　- \(.name) (\(.desc // "SBOM"))"' 2>/dev/null)
  SECTIONS="${SECTIONS}**▪ SBOM/VEX 产物**(已归档流水线产物)
${sbom_list}
"
fi

[ "$has_any" = "1" ] || { log "sec-results/ 下无扫描结果，跳过通知"; exit 0; }
[ -n "$NOTIFY_WEBHOOK" ] || { log "未配置 NOTIFY_WEBHOOK，跳过推送(结果见流水线日志与产物)"; exit 0; }

TITLE="${NOTIFY_TITLE_PREFIX}"
[ -n "$BUILD_URL" ] && SECTIONS="${SECTIONS}
**流水线**: [查看运行记录](${BUILD_URL})"

BODY="### ${TITLE}
${SECTIONS}"

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
      local at_line=""
      [ -n "$NOTIFY_AT" ] && at_line=" @${NOTIFY_AT//,/ @}"
      payload=$(jq -n --arg t "$TITLE" --arg b "${BODY}${at_line}" \
        --arg ats "$NOTIFY_AT" \
        '{msgtype:"markdown",markdown:{title:$t,text:$b},
          at:{atMobiles:($ats|split(",")|map(select(length>0))),isAtAll:false}}')
      ;;
    wecom)
      payload=$(jq -n --arg c "$BODY" '{msgtype:"markdown",markdown:{content:$c}}')
      ;;
    feishu)
      local plain
      plain=$(printf '★ %s' "$BODY" | sed -e 's/^★ ### /★ /' -e 's/\*\*//g' -e 's/　/ /g')
      payload=$(jq -n --arg t "$plain" '{msg_type:"text",content:{text:$t}}')
      ;;
    *)
      warn "未知 NOTIFY_TYPE=$NOTIFY_TYPE，跳过推送"; return 0 ;;
  esac
  resp=$(curl -s $TLS_FLAGS --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$url")
  log "推送返回: $resp"
  echo "$resp" | grep -qiE '"errcode":0|"StatusCode":0|"code":0' && return 0
  return 1
}

# 失败重试一次（webhook 瞬时抖动很常见）
if send_once; then
  log "聚合通知已推送"
else
  warn "首次推送未确认成功，5秒后重试一次..."
  sleep 5
  send_once || warn "推送仍未确认成功(结果不影响扫描结论，请检查机器人配置/关键词)"
fi
exit 0
