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
#    NOTIFY_AT_ON_FAIL=1          默认: 仅门禁阻断时@手机号(0=总是@)
#  退出码: 0=推送成功或未配置webhook  2=环境错误
# ============================================================================
set -uo pipefail
# 抵消CI外层(云效等)可能继承的 errexit: 本脚本全程显式错误处理, 不依赖 -e
set +e
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
NOTIFY_TITLE_PREFIX="${NOTIFY_TITLE_PREFIX:-🛡️ 安全扫描}"
BUILD_URL="${BUILD_URL:-}"
REPO_LABEL="${REPO_LABEL:-}"                  # 卡片标题仓库名(缺省取应用名去分支后缀)
TLS_INSECURE="${TLS_INSECURE:-1}"
[ "$TLS_INSECURE" = "1" ] && TLS_FLAGS="-k" || TLS_FLAGS=""

urlencode() { printf '%s' "$1" | jq -sRr '@uri'; }

# ---- 读取结果文件 ----
rj() { if [ -f "$1" ]; then cat "$1"; else echo '{}'; fi; }
SAST=$(rj "$RESULT_DIR/codeai-result.json")
SCA=$(rj "$RESULT_DIR/sca-result.json")
SCAA=$(rj "$RESULT_DIR/sca-result-artifact.json")
SBOM=$(rj "$RESULT_DIR/sbom-info.json")

has_any=0

# ---- SKU/业务线（从任一结果JSON提取; 命名体系v3） ----
SKU_LABEL=""
for _f in "$SAST" "$SCA"; do
  _sku=$(echo "$_f" | jq -r '.sku // empty' 2>/dev/null)
  if [ -n "$_sku" ]; then
    _biz=$(echo "$_f" | jq -r '.biz // empty' 2>/dev/null)
    SKU_LABEL="SKU ${_sku}"; [ -n "$_biz" ] && SKU_LABEL="${_biz} 品线 · SKU ${_sku}"
    break
  fi
done

verdict_tag=""

# ---- SAST 平台现查模式: 云效三步场景, 步骤2通知时无本地SAST结果文件, 从平台API查最新统计 ----
if [ "$(echo "$SAST" | jq -r '.appName // empty' 2>/dev/null)" = "" ] \
   && [ -n "${SAST_URL:-}" ] && [ -n "${SAST_TOKEN:-}" ] && [ -n "${APP_NAME:-}" ]; then
  _tl=""; [ "${TLS_INSECURE:-0}" = "1" ] && _tl="-k"
  _pname=$(echo "$SAST" | jq -r '.projectName // empty' 2>/dev/null)
  [ -z "$_pname" ] && _pname="${SAST_PROJECT_NAME:-${APP_NAME%-*}}"
  _proj=$(curl -s $_tl --max-time 60 -G --url "${SAST_URL}/sast/api-v1/open-api/project/page" \
    --data-urlencode "pageNum=1" --data-urlencode "pageSize=50" \
    --header "Sast-Token: ${SAST_TOKEN}" 2>/dev/null)
  _proj_id=$(echo "$_proj" | jq -r --arg n "$_pname" '[.data.records[]? | select(.projectName==$n) | (.projectId|tostring)] | if length>0 then (max) else "" end' 2>/dev/null)
  _app_id=""
  if [ -n "$_proj_id" ]; then
    _resp=$(curl -s $_tl --max-time 60 --url "${SAST_URL}/sast/api-v1/open-api/app/info/${_proj_id}?appName=${APP_NAME}&pageNum=1&pageSize=50" --header "Sast-Token: ${SAST_TOKEN}" 2>/dev/null)
    _app_id=$(echo "$_resp" | jq -r --arg n "$APP_NAME" '[.data.records[]? | select(.appName==$n) | (.appId|tostring)] | if length>0 then (max) else "" end' 2>/dev/null)
  fi
  if [ -n "$_app_id" ] && [ "$_app_id" != "null" ]; then
    _st=""
    _best=0
    _recs=$(curl -s $_tl --max-time 60 --url "${SAST_URL}/sast/api-v1/open-api/app/records/${_app_id}" --header "Sast-Token: ${SAST_TOKEN}" 2>/dev/null)
    # 取全量口径: 历史任务中缺陷总数最大的一条(status=3 已完成)
    _best_rec=$(echo "$_recs" | jq -c '[.data[]? | select(.status==3)] | if length>0 then (sort_by(-((.superCount//0)+(.highCount//0)+(.middleCount//0)+(.lowCount//0)))[0]) else empty end' 2>/dev/null)
    if [ -n "$_best_rec" ] && [ "$_best_rec" != "null" ]; then
      sup=$(echo "$_best_rec" | jq -r '.superCount // 0'); high=$(echo "$_best_rec" | jq -r '.highCount // 0')
      mid=$(echo "$_best_rec" | jq -r '.middleCount // 0'); low=$(echo "$_best_rec" | jq -r '.lowCount // 0')
      _st="ok"; _best=1
    else
      _st=$(curl -s $_tl --max-time 60 --url "${SAST_URL}/sast/api-v1/open-api/defect/jenkins/result?appId=${_app_id}" --header "Sast-Token: ${SAST_TOKEN}" 2>/dev/null)
      sup=$(echo "$_st" | jq -r '[.data.openJenkinsFlawInfoMap[].superCount] | add // 0' 2>/dev/null)
      high=$(echo "$_st" | jq -r '[.data.openJenkinsFlawInfoMap[].highCount] | add // 0' 2>/dev/null)
      mid=$(echo "$_st" | jq -r '[.data.openJenkinsFlawInfoMap[].middleCount] | add // 0' 2>/dev/null)
      low=$(echo "$_st" | jq -r '[.data.openJenkinsFlawInfoMap[].lowCount] | add // 0' 2>/dev/null)
    fi
    case "${sup}${high}${mid}${low}" in *null*|"") sup=0; high=0; mid=0; low=0 ;; esac
    if [ "$((_best + 1))" = "1" ]; then log "SAST 统计已从平台现查(${APP_NAME}): ${sup}/${high}/${mid}/${low}"; fi
    SAST=$(jq -n --arg app "$APP_NAME" --argjson s "$sup" --argjson h "$high" --argjson m "$mid" --argjson l "$low" \
      --arg url "${SAST_URL}" --arg aid "$_app_id" \
      '{appName:$app, defectCount:{super:$s, high:$h, middle:$m, low:$l}, platformUrl:$url,
        detailUrl:($url+"/detection/code/"+$aid+"/details/result"), gateResult:"未启用(仅告警)", scanMode:"平台最新"}')
  fi
fi

# ---- SCA 统计兜底: 扫描窗口内未就绪时(平台聚合滞后2-3分钟), 通知阶段补查 ----
if [ "$(echo "$SCA" | jq -r '.vulNum // empty' 2>/dev/null)" = "" ] \
   && [ "$(echo "$SCA" | jq -r '.taskId // empty' 2>/dev/null)" != "" ] \
   && [ -n "${SCA_URL:-}" ] && [ -n "${SCA_USER_TOKEN:-}" ] && command -v curl >/dev/null 2>&1; then
  _tid=$(echo "$SCA" | jq -r '.taskId')
  _api=$(echo "$SCA_URL" | sed 's/:30001/:30002/')
  for _try in 1 2 3 4 5 6 7 8 9 10; do
    _stat=$(curl -s -k --max-time 30 -H "OpenApiUserToken: ${SCA_USER_TOKEN}" "${_api}/openapi/v1/task/${_tid}" 2>/dev/null)
    if echo "$_stat" | grep -q '"code":0'; then
      _patch=$(echo "$_stat" | jq -c '{componentNum, componentSeriousNum, componentHighNum, componentMediumNum, componentLowNum, componentNormalNum, vulNum, vulSeriousNum, vulHighNum, vulMediumNum, vulLowNum, licenseNum, licenseHighNum, licenseMediumNum, licenseLowNum} | with_entries(select(.value!=null))' 2>/dev/null)
      if [ "$(echo "$_patch" | jq -r '.vulNum // empty' 2>/dev/null)" != "" ]; then
        SCA=$(echo "$SCA" | jq -c --argjson p "$_patch" '. + $p')
        log "SCA 统计已补齐(vulNum=$(echo "$_patch" | jq -r '.vulNum'))"
        break
      fi
    fi
    [ "$_try" = "10" ] || { sleep 60; log "SCA 统计未就绪, 60秒后补查($_try/10)"; }
  done
fi

verdict=""

# ================= 摘要数字(首行引用块, 一眼看明白) =================
HEADLINE=""
META_LINE=""
GATE_LINES=""
SAST_LINE=""
SCA_LINES=""
ART_LINE=""

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
  commit=$(echo "$SAST" | jq -r '.commit // empty')
  is_inc=$(echo "$SAST" | jq -r '.incremental // false')
  [ -z "$REPO_LABEL" ] && REPO_LABEL="${app%-*}"
  sast_total=$((sup + high + mid + low))
  HEADLINE="代码缺陷 **${sast_total}**（🔴${sup} 🟠${high} 🟡${mid} ⚪${low}）"
  # 增量口径注记(短): 平铺文案避免嵌套括号
  mode_txt="$mode"
  [ "$is_inc" = "true" ] && mode_txt="增量扫描·仅变更文件"
  detail_url=$(echo "$SAST" | jq -r '.detailUrl // empty')
  [ -z "$detail_url" ] && detail_url=$(echo "$SAST" | jq -r '.reportUrl // empty')
  case "$gate" in
    *不通过*) verdict_tag="⛔ 门禁未通过"; GATE_LINES="- 源码门禁：⛔ 未通过" ;;
    *通过*)   verdict_tag="✅ 门禁通过";   GATE_LINES="- 源码门禁：✅ 通过" ;;
    *)        verdict_tag="📋 检出摘要（门禁未启用）"; sast_gate_line="未启用（仅统计不阻断）" ;;
  esac
  sast_url_line="${detail_url:-}"
  sast_line_txt="**源码检测**（${mode_txt}）"
  [ -n "$detail_url" ] && sast_line_txt="${sast_line_txt} ｜ [缺陷详情 →](${detail_url})"
  SAST_LINE="$sast_line_txt"
  META_LINE="${branch:+${branch} ｜ }$(printf '%.8s' "${commit:-}")${author:+ ｜ ${author}}${stime:+ ｜ ${stime}}"
fi

if [ "$(echo "$SCA" | jq -r '.appName // empty' 2>/dev/null)" != "" ]; then
  has_any=1
  app=$(echo "$SCA" | jq -r '.appName')
  url=$(echo  "$SCA" | jq -r '.resultUrl // ""')
  gate=$(echo "$SCA" | jq -r '.gate // "未启用"')
  [ -z "$REPO_LABEL" ] && REPO_LABEL="${app%-*}"
  v=$(echo "$SCA" | jq -r '.vulNum // empty')
  if [ -n "$v" ]; then
    sca_v="$v"
    vs=$(echo "$SCA" | jq -r '.vulSeriousNum // 0'); vh=$(echo "$SCA" | jq -r '.vulHighNum // 0')
    vm=$(echo "$SCA" | jq -r '.vulMediumNum // 0'); vl=$(echo "$SCA" | jq -r '.vulLowNum // 0')
    sca_vs=$vs; sca_vh=$vh; sca_vm=$vm; sca_vl=$vl
    sca_comp=$(echo "$SCA" | jq -r '.componentNum // 0')
    sca_cs=$(echo "$SCA" | jq -r '.componentSeriousNum // 0'); sca_ch=$(echo "$SCA" | jq -r '.componentHighNum // 0')
    sca_cm=$(echo "$SCA" | jq -r '.componentMediumNum // 0'); sca_cn=$(echo "$SCA" | jq -r '.componentNormalNum // 0')
    sca_lic=$(echo "$SCA" | jq -r '.licenseNum // 0'); sca_lh=$(echo "$SCA" | jq -r '.licenseHighNum // 0')
    _sep="　｜　"; [ -z "$HEADLINE" ] && _sep=""
    HEADLINE="${HEADLINE}${_sep}开源漏洞 **${v}**（🔴${vs} 🟠${vh} 🟡${vm} ⚪${vl}）"
    HEADLINE2="组件 **$(echo "$SCA" | jq -r '.componentNum // 0')**（🔴$(echo "$SCA" | jq -r '.componentSeriousNum // 0') 🟠$(echo "$SCA" | jq -r '.componentHighNum // 0') 🟡$(echo "$SCA" | jq -r '.componentMediumNum // 0') ✅$(echo "$SCA" | jq -r '.componentNormalNum // 0')）　许可证 **$(echo "$SCA" | jq -r '.licenseNum // 0')** 项（🔴高风险 $(echo "$SCA" | jq -r '.licenseHighNum // 0')）"
    # 组件/许可证行(基础数据)
    comp_line=""
    if [ "$(echo "$SCA" | jq -r '.componentNum // empty')" != "" ]; then
      comp_line="组件 **$(echo "$SCA" | jq -r '.componentNum')** 个（🔴$(echo "$SCA" | jq -r '.componentSeriousNum // 0') 🟠$(echo "$SCA" | jq -r '.componentHighNum // 0') 🟡$(echo "$SCA" | jq -r '.componentMediumNum // 0') ✅$(echo "$SCA" | jq -r '.componentNormalNum // 0')）"
    fi
    lic_line=""
    if [ "$(echo "$SCA" | jq -r '.licenseNum // empty')" != "" ]; then
      lic_line="许可证 **$(echo "$SCA" | jq -r '.licenseNum')** 项（🔴高风险 $(echo "$SCA" | jq -r '.licenseHighNum // 0')）"
    fi
    SCA_LINES=""
  fi
  case "$gate" in
    *⛔*|*不通过*) sca_gate_line="⛔ 未通过"; verdict_tag="⛔ 门禁未通过"; GATE_LINES="${GATE_LINES:+${GATE_LINES}
}- SCA红线：⛔ 未通过" ;;
    *通过*|*✅*)   sca_gate_line="✅ 通过"; GATE_LINES="${GATE_LINES:+${GATE_LINES}
}- SCA红线：✅ 通过" ;;
    *)             sca_gate_line="未启用" ;;
  esac
  sca_line="${url:-}"
  sca_line_txt="**组件检测**（依赖分析）"
  [ -n "$url" ] && sca_line_txt="${sca_line_txt} ｜ [检测报告(免登录) →](${url})"
  SCA_MAIN_LINE="$sca_line_txt"
fi

# 制品扫描(如有)
if [ "$(echo "$SCAA" | jq -r '.appName // empty' 2>/dev/null)" != "" ]; then
  has_any=1
  aurl=$(echo "$SCAA" | jq -r '.resultUrl // ""')
  av=$(echo "$SCAA" | jq -r '.vulNum // empty')
  art_txt="**制品检测**（固件/产物成分）"
  [ -n "$av" ] && art_txt="${art_txt}：漏洞 ${av}（🔴$(echo "$SCAA" | jq -r '.vulSeriousNum // 0') 🟠$(echo "$SCAA" | jq -r '.vulHighNum // 0')）"
  [ -n "$aurl" ] && art_txt="${art_txt} ｜ [报告 →](${aurl})"
  ART_LINE="$art_txt"
fi

# SBOM 产物(一行)
SBOM_LINE=""
if [ "$(echo "$SBOM" | jq -r '.files // [] | length' 2>/dev/null)" != "0" ]; then
  has_any=1
  sbom_kinds=$(echo "$SBOM" | jq -r '.files | group_by(.desc)[] | (.[0].desc)' 2>/dev/null | sed 'N;s/\n/ ｜ /g')
  SBOM_LINE="SBOM/VEX 产物已归档：${sbom_kinds}"
fi

[ "$has_any" = "1" ] || { log "sec-results/ 下无扫描结果，跳过通知"; exit 0; }
[ -n "$NOTIFY_WEBHOOK" ] || { log "未配置 NOTIFY_WEBHOOK，跳过推送(结果见流水线日志与产物)"; exit 0; }

# ================= 拼装 =================
[ -n "$verdict_tag" ] || verdict_tag="📋 检出摘要（门禁未启用）"

# ---- 统一裁决: ✅门禁通过 但存在未启用门禁时, 明示范围避免误读 ----
if [ "$verdict_tag" = "✅ 门禁通过" ]; then
  _mixed=0
  echo "$SAST" | jq -r '.gateResult // "未启用"' 2>/dev/null | grep -q "未启用" && _mixed=1
  echo "$SCA"  | jq -r '.gate // "未启用"' 2>/dev/null    | grep -q "未启用" && _mixed=1
  [ "$_mixed" = "1" ] && verdict_tag="✅ 门禁通过（部分门禁未启用）"
fi

TITLE="${NOTIFY_TITLE_PREFIX}｜${REPO_LABEL:-应用}${SKU_LABEL:+｜${SKU_LABEL}}"

# ---- 正文: 每行 "- " 列表前缀(钉钉markdown单\n不换行, 列表才可靠分行) ----
BODY="## ${REPO_LABEL:-应用} · 安全扫描 ${verdict_tag}

> ${HEADLINE}

- 🖥 源码检测（${mode_txt:-}）: 缺陷 ${sast_total:-0}（🔴${sup:-0} 🟠${high:-0} 🟡${mid:-0} ⚪${low:-0}）
- 门禁: ${sast_gate_line:-未启用（仅统计）}
- 📦 组件检测: 漏洞 ${sca_v:-0}（🔴${sca_vs:-0} 🟠${sca_vh:-0} 🟡${sca_vm:-0} ⚪${sca_vl:-0}）
- 组件 ${sca_comp:-0} 个（🔴${sca_cs:-0} 🟠${sca_ch:-0} 🟡${sca_cm:-0} ✅${sca_cn:-0}）｜ 许可证 ${sca_lic:-0} 项（🔴高风险 ${sca_lh:-0}）
${sca_line:+- [SCA 检测报告（免登录直达） →](${sca_line})
}${sast_url_line:+- [SAST 缺陷详情与跟踪路径 →](${sast_url_line})
}- 📎 产物已归档: ${SBOM_SHORT:-SPDX SBOM · CSAF VEX · PDF · Excel}${BUILD_URL:+
- [全套报告下载 →](${BUILD_URL})}"

# ---- 超长保护: 钉钉 markdown 消息上限约20KB, 超长会发送失败——截断并提示 ----
_body_len=$(printf '%s' "$BODY" | wc -c | tr -d ' ')
if [ "$_body_len" -gt 18000 ]; then
  warn "卡片内容${_body_len}字节超过钉钉上限, 截断保护(完整数据见流水线产物)"
  BODY="$(printf '%.17000s' "$BODY")

> ⚠️ 内容过长已截断，完整缺陷清单与报告见下方链接"
fi

# ---- 调试出口: NOTIFY_DRY_RUN=1 打印卡片内容不推送(排障用) ----
if [ "${NOTIFY_DRY_RUN:-0}" = "1" ]; then
  echo "======== DRY RUN: TITLE ========"
  echo "$TITLE"
  echo "======== DRY RUN: BODY ========"
  echo "$BODY"
  exit 0
fi

# ---- @策略: 默认仅门禁未通过时@NOTIFY_AT; NOTIFY_AT_ON_FAIL=0 时总是@ ----
at_now=0
[ "$verdict_tag" = "⛔ 门禁未通过" ] && at_now=1
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
      [ "$at_now" = "1" ] && [ -n "$NOTIFY_AT" ] && at_mobiles=$(echo "$NOTIFY_AT" | tr -d ' ' | jq -Rc 'split(",") | map(select(length>0))')
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
