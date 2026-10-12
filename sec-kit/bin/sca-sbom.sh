#!/usr/bin/env bash
# ============================================================================
#  源鉴SCA SBOM+VEX 导出 (sca-sbom.sh) v2 · 配合 sca-scan.sh 使用
# ----------------------------------------------------------------------------
#  v2 变化(2026-10-12 重写): 改用 OpenAPI 专用接口直接生成指定格式，
#  不再依赖"报告中心猜 type=4 记录"的旧通道(保留为兜底)。
#
#  产物(全部落盘 OUT_DIR 并登记 sbom-info.json 供 sec-notify.sh 汇总):
#    sbom_<应用名>.spdx.json     SPDX 2.3 SBOM 清单(sbomType=1, sbomFormat=4)
#    vex_<应用名>.csaf.json      CSAF 2.0 VEX 漏洞交换报告(format=2)
#    sbom_<应用名>.cyclonedx.json CycloneDX 1.6(SBOM_TYPES 含 cyclonedx 时)
#  接口(2026-10-12 sca.igovee.com v4.13.0 实测):
#    生成SBOM  POST :30002/openapi/v1/sbom/report/applications
#              {applicationIds, reportName, sbomFormat, sbomType}
#              sbomType: 1=SPDX 2=CycloneDX 3=SWID 4=DSDX 5/6=BOM-SW 7=SBOMDF
#              sbomFormat: 4=json 8=xml 9=yaml(SPDX) 7=tag/value 10=cbor 11=tag
#    生成VEX   POST :30002/openapi/v1/report/generate/vex
#              {reportName, reportParam:{applicationIdList, format}}
#              format: 1=CycloneDX-VEX(4.13.0实测生成卡死,不建议) 2=CSAF-VEX
#    轮询      POST :30001/sca/api-v1/asset/report/list  (type含4 + name前缀 + status=1)
#    下载      POST :30001/sca/api-v1/asset/report/downLoadReport/batch {idList}
#  用法(CI / 手动):
#    SCA_URL=... SCA_USER_TOKEN=... APP_NAME=<应用名> SCA_APP_ID=<应用ID> \
#    [SBOM_TYPES="spdx vex"] bash sca-sbom.sh
#  退出码: 0=成功(或部分成功但已有兜底产物)  2=失败
# ============================================================================
set -uo pipefail
LOG_PREFIX="[SCA-SBOM]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }
die()  { echo "$LOG_PREFIX [错误] $*" >&2; exit 2; }

: "${SCA_URL:?请设置 SCA_URL}"
: "${SCA_USER_TOKEN:?请设置 SCA_USER_TOKEN}"
SCA_APP_ID="${SCA_APP_ID:-}"
APP_NAME="${APP_NAME:-scan-app}"
OUT_DIR="${OUT_DIR:-./sec-results}"; mkdir -p "$OUT_DIR"
SBOM_TYPES="${SBOM_TYPES:-spdx vex}"      # 空格分隔: spdx vex cyclonedx
SBOM_WAIT_SECONDS="${SBOM_WAIT_SECONDS:-240}"   # 生成等待上限(大项目流式导出较慢)
DL_TIMEOUT="${DL_TIMEOUT:-600}"
AUTH_USER="OpenApiUserToken: ${SCA_USER_TOKEN}"
RESULT_INFO_FILE="${RESULT_DIR:-$OUT_DIR}/sbom-info.json"

for cmd in curl jq; do command -v "$cmd" >/dev/null 2>&1 || die "缺少命令 [$cmd]"; done

TLS_INSECURE="${TLS_INSECURE:-1}"
[ "$TLS_INSECURE" = "1" ] && TLS_FLAGS="-k" || TLS_FLAGS=""

ROOT_FMT=$(echo "$SCA_URL" | awk -F"/" '{ print $1"/"$2"/"$3 }')
API_ROOT=$(echo "$ROOT_FMT" | sed 's/:30001/:30002/')
LIST_EP="${ROOT_FMT}/sca/api-v1/asset/report/list"
DL_EP="${ROOT_FMT}/sca/api-v1/asset/report/downLoadReport/batch"
GEN_SBOM_EP="${API_ROOT}/openapi/v1/sbom/report/applications"
GEN_VEX_EP="${API_ROOT}/openapi/v1/report/generate/vex"

safe_name=$(printf '%s' "$APP_NAME" | tr -c 'A-Za-z0-9._-' '_')

# ---- ① 触发生成: 按类型逐一提交，返回 名称前缀 列表用于轮询 ----
TRIGGERS=()
gen_sbom() {  # gen_sbom <sbomType> <fmt> <name>
  local resp
  resp=$(curl -s $TLS_FLAGS --max-time 60 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" \
    -d "$(jq -n --argjson ids "[${SCA_APP_ID:-0}]" --arg rn "$3" \
        --argjson st "$1" --argjson sf "$2" \
        '{applicationIds:$ids, reportName:$rn, sbomFormat:$sf, sbomType:$st}')" \
    "$GEN_SBOM_EP")
  if echo "$resp" | grep -q '"code":0'; then
    log "SBOM 生成已受理: $3 (sbomType=$1)"; return 0
  fi
  warn "SBOM 生成未受理($3): $(echo "$resp" | head -c 150)"; return 1
}
gen_vex() {  # gen_vex <format> <name>
  local resp
  resp=$(curl -s $TLS_FLAGS --max-time 60 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" \
    -d "$(jq -n --arg rn "$2" --argjson fmt "$1" --argjson ids "[${SCA_APP_ID:-0}]" \
        '{reportName:$rn, reportParam:{applicationIdList:$ids, format:$fmt}}')" \
    "$GEN_VEX_EP")
  if echo "$resp" | grep -q '"code":0'; then
    log "VEX 生成已受理: $2 (format=$1)"; return 0
  fi
  warn "VEX 生成未受理($2): $(echo "$resp" | head -c 150)"; return 1
}

log "==== SBOM+VEX 导出开始 (应用=${APP_NAME} appId=${SCA_APP_ID:-未提供}) ===="
if [ -z "$SCA_APP_ID" ]; then
  die "未设置 SCA_APP_ID(来自 sca-scan.sh 结果 JSON 的 appId 字段)"
fi

STAMP=$(date +%Y%m%d%H%M%S)
for t in $SBOM_TYPES; do
  case "$t" in
    spdx)      gen_sbom 1 4 "sbom-${safe_name}-spdx-${STAMP}" && TRIGGERS+=("【SPDX-json】sbom-${safe_name}-spdx-${STAMP}|spdx") ;;
    cyclonedx) gen_sbom 2 4 "sbom-${safe_name}-cdx-${STAMP}"  && TRIGGERS+=("【CycloneDX-json】sbom-${safe_name}-cdx-${STAMP}|cyclonedx") ;;
    vex)       gen_vex  2   "vex-${safe_name}-${STAMP}"       && TRIGGERS+=("【VEX-CSAF】vex-${safe_name}-${STAMP}|vex") ;;
    *) warn "未知 SBOM 类型 [$t]，跳过(可用: spdx vex cyclonedx)" ;;
  esac
done
[ "${#TRIGGERS[@]}" -ge 1 ] || die "没有任何导出被受理(请检查 SCA_USER_TOKEN 权限与应用状态)"

# ---- ② 轮询报告中心：按【格式前缀+名称前缀】找 status=1 的最新记录 ----
find_record() {  # find_record <显示名前缀(含【】)> → 输出 id
  local want="$1" page=1 resp id total
  while :; do
    resp=$(curl -s $TLS_FLAGS --max-time 30 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" \
      -d "{\"pageNum\":${page},\"pageSize\":50}" "$LIST_EP")
    [ "$(echo "$resp" | jq -r '.code // -1' 2>/dev/null)" = "0" ] || return 1
    id=$(echo "$resp" | jq -r --arg w "$want" \
      '.data.records[]? | select(.status==1) | select(.name | startswith($w)) | .id' 2>/dev/null | sort -n | tail -n1)
    [ -n "$id" ] && [ "$id" != "null" ] && { echo "$id"; return 0; }
    total=$(echo "$resp" | jq -r '.data.total // 0' 2>/dev/null); total=${total:-0}
    [ $(( page * 50 )) -ge "$total" ] && return 1
    page=$(( page + 1 ))
  done
}

download_to() {  # download_to <recordId> <outfile>
  local rid="$1" out="$2" attempt head
  for attempt in 1 2; do
    curl -s $TLS_FLAGS --max-time "$DL_TIMEOUT" -X POST -H "Content-Type: application/json" -H "$AUTH_USER" \
      -d "{\"idList\":[${rid}]}" "$DL_EP" -o "$out"
    head=$(head -c 300 "$out" 2>/dev/null)
    # 平台错误会返回 JSON(code字段)；正常产物是纯 SBOM/VEX JSON
    if echo "$head" | grep -q '"code"'; then
      warn "下载返回平台错误(attempt=${attempt}): $(echo "$head" | head -c 120)"
    elif head -c 1 "$out" 2>/dev/null | grep -qE '[{[]' && \
         { [ ! -x "$(command -v python3)" ] || python3 -c "import json;json.load(open('$out'))" 2>/dev/null; }; then
      return 0
    fi
    [ "$attempt" = "1" ] && { sleep 5; log "重试下载(可能传输截断)"; }
  done
  rm -f "$out"; return 1
}

# ---- ③ 逐个等待+下载+校验 ----
# 注: 不用关联数组(兼容 macOS bash3.2 与老版本执行机)
OUT_SPDX=""; OUT_CDX=""; OUT_VEX=""
waited_total=0
pending=("${TRIGGERS[@]}")
while [ "${#pending[@]}" -ge 1 ] && [ "$waited_total" -lt "$SBOM_WAIT_SECONDS" ]; do
  next=""
  for item in "${pending[@]}"; do
    prefix="${item%%|*}"; kind="${item##*|}"
    rid=$(find_record "$prefix")
    if [ -n "$rid" ]; then
      case "$kind" in
        spdx)      out="${OUT_DIR}/sbom_${safe_name}.spdx.json" ;;
        cyclonedx) out="${OUT_DIR}/sbom_${safe_name}.cyclonedx.json" ;;
        vex)       out="${OUT_DIR}/vex_${safe_name}.csaf.json" ;;
      esac
      if download_to "$rid" "$out"; then
        log "已下载: $out ($(du -h "$out" | cut -f1), 记录id=${rid})"
        case "$kind" in
          spdx) OUT_SPDX="$out" ;;
          cyclonedx) OUT_CDX="$out" ;;
          vex) OUT_VEX="$out" ;;
        esac
      else
        warn "下载校验失败: $prefix (id=${rid})"
      fi
    else
      next="${next}${item}
"
    fi
  done
  # 重建 pending 数组
  pending=()
  while IFS= read -r _p; do [ -n "$_p" ] && pending+=("$_p"); done <<< "$next"
  [ "${#pending[@]}" -ge 1 ] || break
  sleep 15; waited_total=$((waited_total + 15))
  log "等待生成中... ${waited_total}s (剩余 ${#pending[@]} 项)"
done
if [ "${#pending[@]}" -ge 1 ]; then
  for item in "${pending[@]}"; do warn "超时未生成: ${item%%|*}"; done
fi

# ---- ④ SPDX 内容完整性抽查 + 产物清单落盘 ----
if [ -n "${OUT_SPDX:-}" ] && command -v python3 >/dev/null 2>&1; then
  pkgs=$(python3 -c "
import json
try:
    d=json.load(open('${OUT_SPDX}'))
    print(len(d.get('packages') or []))
except Exception:
    print(-1)
" 2>/dev/null)
  case "$pkgs" in
    ''|*-1) warn "SPDX 文件校验失败(可能截断)，请人工打开确认" ;;
    0)      warn "SPDX 组件数为 0——上游扫描可能未识别到依赖，请确认特征文件已提交" ;;
    *)      log "SPDX 校验通过: ${pkgs} 个组件, 版本 $(python3 -c "import json;print(json.load(open('${OUT_SPDX}')).get('spdxVersion','?'))" 2>/dev/null)" ;;
  esac
fi

FILES_JSON="[]"
for kv in "spdx:${OUT_SPDX:-}" "cyclonedx:${OUT_CDX:-}" "vex:${OUT_VEX:-}"; do
  kind="${kv%%:*}"; f="${kv#*:}"
  [ -n "$f" ] || continue
  case "$kind" in
    spdx)      desc="SPDX 2.3 组件清单" ;;
    cyclonedx) desc="CycloneDX 1.6 组件清单" ;;
    vex)       desc="CSAF 2.0 VEX 漏洞交换" ;;
  esac
  FILES_JSON=$(echo "$FILES_JSON" | jq -c --arg n "$(basename "$f")" --arg d "$desc" '. + [{name:$n, desc:$d}]')
done
if [ "$FILES_JSON" != "[]" ]; then
  jq -n --arg app "$APP_NAME" --argjson f "$FILES_JSON" \
    '{appName:$app, generatedAt:(now|todate), files:$f}' > "$RESULT_INFO_FILE"
  log "产物清单已写入: ${RESULT_INFO_FILE}"
  echo "SBOM_INFO_FILE=${RESULT_INFO_FILE}"
  echo "SBOM_FILES=$(printf '%s ' ${OUT_SPDX:-} ${OUT_CDX:-} ${OUT_VEX:-})"
  exit 0
fi
die "全部导出失败(见上方警告；也可稍后在平台 报告管理 手动导出)"
