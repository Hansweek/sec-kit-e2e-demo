#!/usr/bin/env bash
# ============================================================================
#  源鉴SCA × Gitee 一体化脚本 (sca-scan.sh) · 单文件版
# ----------------------------------------------------------------------------
#  一个文件包含 SCA 对接全部能力：项目创建/依赖扫描/制品扫描/报告导出/制品库上传。
#  所有配置由环境变量注入，换客户/换项目零修改本文件。
#
#  用法（子命令）:
#    sca-scan.sh all        默认。全流程：建项目→依赖扫描→构建→制品扫描→报告→上传
#    sca-scan.sh provision  只建/复用项目（产出 SCA_PROJECT_ID/TOKEN）
#    sca-scan.sh deps       只做组件依赖扫描（当前目录，扫特征文件）
#    sca-scan.sh build      只做构建（Maven优先/tar兜底，可用 BUILD_CMD 覆盖）
#    sca-scan.sh artifact   只做制品扫描（SCAN_DIR + SCAN_PATTERNS）
#    sca-scan.sh report     只做报告生成+下载（需 SCA_APP_ID）
#    sca-scan.sh upload     只上传报告到 Gitee 制品库（需 PKG_URL/PKG_USER/PKG_PASS）
#    sca-scan.sh writeback  只回写 Gitee（commit状态/MR评论，需 MR_TOKEN/MR_OWNER/MR_REPO+结果JSON）
#
#  ====== 变量表（全部环境变量，按流水线/执行机方式注入）======
#  【必需】
#    SCA_URL            平台Web地址，如 https://IP:30001
#    SCA_USER_TOKEN     用户Token（个人中心-个人令牌；建项目/扫描/报告通用）
#  【扫描】
#    APP_NAME           应用名（默认 仓库名-分支；同名自动版本对比/增量）
#    SCAN_DIR           扫描目录（默认 ${PWD}）
#    SCAN_PATTERNS      制品模式正则（设置后只收集匹配文件，如 '.*\.(jar|war)$'）
#    DEPS_GATE          依赖扫描门禁(默认1)   ARTIFACT_GATE   制品扫描门禁(默认1)
#    BY_PASS            平台异常放行(默认1)   TIMEOUT_MINUTES 超时分钟(默认90)
#    TASK_SOURCE        任务来源标签(5=GiteeGo 9=通用Shell，默认9)
#    ARTIFACT_SUFFIX    卡点二应用名后缀(默认 -artifact，可按客户命名规范改)
#    PRIVATE_REPO_IDS   私服仓库ID(逗号分隔)
#    ENGINE_TOKEN       红线引擎键值(默认官方脚本内置值)
#  【构建(all模式)】
#    BUILD_CMD          构建命令(默认自动探测 mvn→gradle→npm→tar兜底)
#  【报告】
#    REPORT_ENABLED     报告生成+下载开关(all模式默认1)
#    REPORT_NAME        报告名(默认 <APP_NAME>-report)
#    SCA_APP_ID         应用ID(all模式自动从扫描获取；report 单独调用时必填)
#    TASK_ID            扫描任务ID(同上)
#  【制品库】
#    PKG_URL      制品库通用仓库上传地址   PKG_USER/PASS 账号
#    PKG_ENABLED        上传开关(all模式默认1，未配PKG_URL时自动跳过)
#  【项目自动纳管 v2】(2026-10-12)
#    SCA_USERNAME           令牌归属人平台用户名 → 自动设为项目经理+归属其部门
#    SCA_PROJECT_MEMBERS    仓库协作人用户名(逗号分隔) → 自动加入项目成员
#    SCA_PROJECT_SYNC_MEMBERS  1=项目已存在时也尝试同步成员/负责人(project/edit)
#  【SBOM/VEX v2】
#    AUTO_SBOM              1=deps扫描完成后自动导出 SBOM+VEX(默认1)
#    SBOM_TYPES             导出类型,空格分隔(默认"spdx vex"; 可加 cyclonedx)
#  【通知/其它】
#    NOTIFY_WEBHOOK     钉钉/企微/飞书群机器人   NOTIFY_TYPE  dingtalk|wecom|feishu
#    RESULT_JSON_FILE   结果JSON落盘路径(供Gitee回写等下游消费)
#    GIT_BRANCH/GIT_COMMIT/GIT_AUTHOR  CI注入的仓库信息(缺省自动读取)
#
#  依赖: curl(必需)、jq(可选，无则自动降级grep/sed解析)、git/tar/split/md5(系统自带)
#  接口(全部实测验证，SCA 4.13):
#    项目管理  POST :30002/openapi/v1/project/list|create   （用户Token直连，无需登录）
#    扫描链路  POST /sca/api-v1/open-api-v1/…                （OpenApiUserToken+ProjectToken）
#    红线判定  POST /sca/api-v1/engine/rule/handle/rule
#    报告链路  POST /sca/api-v1/asset/report/application/sca/generate（生成，新版本实测）
#              POST /sca/api-v1/report/generate/detection（生成，4.13 实测，自动回退）
#              POST /sca/api-v1/asset/report/notice/download（TXT 快速导出，旧路径）
#              POST /sca/api-v1/asset/report/list（查询，status==1 已生成）
#              POST /sca/api-v1/asset/report/downLoadReport/batch（下载，{"idList":[ID]}）
#  退出码: 0=成功  1=门禁未通过  2=脚本/环境错误
# ============================================================================
set -uo pipefail
# 抵消CI外层(云效等)可能继承的 errexit: 本脚本全程显式错误处理, 不依赖 -e
set +e

# ============================================================================
# 【公共区】配置默认值与工具函数
# ============================================================================
LOG_PREFIX="[SCA]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }
die()  { echo "$LOG_PREFIX [错误] $*" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || die "缺少 curl"

# jq 可选：无 jq 自动降级为 grep/sed 解析（与官方脚本同口径）
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1
field_str() { echo "$1" | sed -n 's/.*"'"$2"'":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1; }
field_num() { echo "$1" | grep -Eo "\"$2\"[[:space:]]*:[[:space:]]*[0-9]+" | head -n1 | grep -Eo '[0-9]+$'; }
json_esc()  { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
md5_file()  { if command -v md5sum >/dev/null 2>&1; then md5sum -b "$1" | awk '{print $1}'; else md5 -q "$1"; fi; }

# 结果推送: 钉钉/企微/飞书群机器人(自足默认, 防CI环境未注入时 set -u 报未绑定)
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
NOTIFY_TYPE="${NOTIFY_TYPE:-dingtalk}"    # dingtalk | wecom | feishu | raw
NOTIFY_SECRET="${NOTIFY_SECRET:-}"        # 钉钉"加签"密钥(未启用则留空)
NOTIFY_AT="${NOTIFY_AT:-}"                # 钉钉@手机号，逗号分隔

SCA_URL="${SCA_URL:-}"
case "$SCA_URL" in
  *:30001*) : ;;
  "") : ;;
  *) [ -n "${SCA_URL:-}" ] && echo "$LOG_PREFIX [提示] SCA_URL 未带 :30001 端口——若平台为标准部署(:30001控制台/:30002 OpenAPI), 请确认地址正确" >&2 ;;
esac
ROOT_FMT=$(echo "$SCA_URL" | awk -F"/" '{ print $1"/"$2"/"$3 }')
API_ROOT=$(echo "$ROOT_FMT" | sed 's/:30001/:30002/')   # OpenAPI服务在30002端口
AUTH_USER="OpenApiUserToken: ${SCA_USER_TOKEN:-}"

# ---- 仓库身份派生（GITEE_REPO/GITEE_BRANCH 优先，git 现场兜底）----
# GITEE_REPO   形如 "namespace/repo"（流水线env），派生：项目名=namespace-repo，应用名=namespace-repo-branch
# GITEE_BRANCH 分支名（流水线env）
derive_repo_identity() {
  GIT_BRANCH_NAME="${GITEE_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo master)}"
  local url="" base=""
  url=$(git config --get remote.origin.url 2>/dev/null || echo "")
  if [ -n "${GITEE_REPO:-}" ]; then
    base=$(basename "${GITEE_REPO%/}" .git)                       # repo 名
    local ns; ns=$(dirname "${GITEE_REPO%/}"); [ "$ns" = "." ] && ns=""
    GITEE_NAMESPACE="$ns"
  elif [ -n "$url" ]; then
    GITEE_NAMESPACE=""
    base=$(basename "$url" .git)
  else
    GITEE_NAMESPACE=""; base=""
  fi
  GITEE_REPO_BASE="$base"
  REPO_IDENT="${GITEE_NAMESPACE:+${GITEE_NAMESPACE}-}${GITEE_REPO_BASE}"
}

# 群通知（可选；钉钉/企微/飞书）
notify_send() {
  [ -z "${NOTIFY_WEBHOOK:-}" ] && return 0
  local title="$1" body="$2" payload
  if [ "$HAVE_JQ" = "1" ]; then
    case "$NOTIFY_TYPE" in
      dingtalk) payload=$(jq -n --arg t "$title" --arg c "$body" '{msgtype:"markdown",markdown:{title:$t,text:$c}}');;
      wecom)    payload=$(jq -n --arg c "$body" '{msgtype:"markdown",markdown:{content:$c}}');;
      feishu)   payload=$(jq -n --arg t "$(echo "$body"|sed 's/\*\*//g')" '{msg_type:"text",content:{text:$t}}');;
      *) return 0;;
    esac
  else
    case "$NOTIFY_TYPE" in
      dingtalk) payload="{\"msgtype\":\"markdown\",\"markdown\":{\"title\":\"$(json_esc "$title")\",\"text\":\"$(json_esc "$body")\"}}";;
      wecom)    payload="{\"msgtype\":\"markdown\",\"markdown\":{\"content\":\"$(json_esc "$body")\"}}";;
      feishu)   payload="{\"msg_type\":\"text\",\"content\":{\"text\":\"$(json_esc "$(echo "$body"|sed 's/\*\*//g')")\"}}";;
      *) return 0;;
    esac
  fi
  curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$NOTIFY_WEBHOOK" >/dev/null || true
}

# ============================================================================
# 【能力1】项目创建/复用 v2（官方 OpenAPI :30002/openapi/v1，用户Token直连）
# ----------------------------------------------------------------------------
# v2(2026-10-12, v4.13.0实测): 自动纳管策略与 SAST 对齐——
#   项目名 = 仓库名(缺省) / SCA_PROJECT_NAME 覆盖
#   项目经理(managerList) = 令牌归属人(配 SCA_USERNAME 自动解析 userId)
#   归属部门(departmentId) = 令牌归属人部门(user/list 返回 departmentId)
#   项目成员(memberList) = 仓库协作人(SCA_PROJECT_MEMBERS, 逗号分隔用户名→userId)
#   已存在项目: SCA_PROJECT_SYNC_MEMBERS=1 时尝试 project/edit 同步成员(幂等)
# ============================================================================
sca_user_lookup() {  # sca_user_lookup <username> → 输出 "userId|departmentId" (空=未找到)
  local u="$1" resp
  [ -n "$u" ] || { echo ""; return; }
  [ "$HAVE_JQ" = "1" ] || { echo ""; return; }
  resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" \
    -H "OpenApiUserToken: ${SCA_USER_TOKEN}" \
    -d "{\"nameList\":[\"${u}\"]}" "${API_ROOT}/openapi/v1/user/list")
  echo "$resp" | jq -r --arg u "$u" \
    '[.data.records[]? | select(.username==$u)] | if length>0 then (.[0] | "\(.userId)|\(.departmentId // 0)") else "" end' 2>/dev/null
}

# ---- 业务标识解析: SKU/业务线(命名体系 v3, 对应9/24会议 SKU分支分层决议) ----
# 来源优先级: 显式变量(SKU_ID/BIZ_LINE) > 分支名模式(sku/<SKU> 或 sku-<SKU>) > 空
# 解析结果写入: 项目描述 / 应用描述 / 结果JSON / 通知卡片 —— 平台可检索, 供VMS/ASOC反推关联
derive_biz_identity() {
  SKU_ID="${SKU_ID:-}"
  BIZ_LINE="${BIZ_LINE:-}"
  if [ -z "$SKU_ID" ]; then
    case "${GIT_BRANCH_NAME:-}" in
      sku/*) SKU_ID="${GIT_BRANCH_NAME#sku/}" ;;
      sku-*) SKU_ID="${GIT_BRANCH_NAME#sku-}" ;;
    esac
  fi
  SEC_META="sec=kit;repo=${REPO_IDENT:-$(basename "$PWD")};branch=${GIT_BRANCH_NAME:-}"
  [ -n "$BIZ_LINE" ] && SEC_META="${SEC_META};biz=${BIZ_LINE}"
  [ -n "$SKU_ID" ]   && SEC_META="${SEC_META};sku=${SKU_ID}"
  [ -n "${CI_PLATFORM:-}" ] && SEC_META="${SEC_META};ci=${CI_PLATFORM}"
  [ -n "$SKU_ID" ] && log "业务标识: SKU=${SKU_ID}${BIZ_LINE:+ 品线=${BIZ_LINE}}(已写入项目/应用描述,平台可检索)"
}

do_provision() {
  [ -n "${SCA_URL:-}" ]    || die "provision: 请设置 SCA_URL"
  [ -n "${SCA_USER_TOKEN:-}" ] || die "provision: 请设置 SCA_USER_TOKEN"
  SCA_PROJECT_NAME="${SCA_PROJECT_NAME:-${REPO_IDENT:-$(basename "$PWD")}}"
  OUT_ENV_FILE="${OUT_ENV_FILE:-./provision.env}"
  log "查找项目: ${SCA_PROJECT_NAME}"
  resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" \
    -H "OpenApiUserToken: ${SCA_USER_TOKEN}" \
    -d "{\"nameOrDescription\":\"${SCA_PROJECT_NAME}\"}" \
    "${API_ROOT}/openapi/v1/project/list")
  echo "$resp" | jq -e '.code == 0' >/dev/null 2>&1 || die "项目查询失败: $(echo "$resp" | head -c 200)"
  FOUND=$(echo "$resp" | jq -c --arg n "$SCA_PROJECT_NAME" \
    '.data.records[] | select(.name==$n) | {id, token}' 2>/dev/null | head -n1)

  # ---- 令牌归属人/成员解析(建项目用) ----
  _owner_id=""; _owner_dept=""
  _line=$(sca_user_lookup "${SCA_USERNAME:-}")
  if [ -n "$_line" ]; then
    _owner_id=$(echo "$_line" | cut -d'|' -f1); _owner_dept=$(echo "$_line" | cut -d'|' -f2)
    log "令牌归属人 ${SCA_USERNAME}: userId=${_owner_id} 部门=${_owner_dept}"
  elif [ -n "${SCA_USERNAME:-}" ]; then
    warn "SCA_USERNAME=${SCA_USERNAME} 未匹配到平台用户(项目将按令牌默认归属创建)"
  fi
  _member_ids=""
  if [ -n "${SCA_PROJECT_MEMBERS:-}" ]; then
    _resolved=""; _missed=""
    for _m in $(echo "$SCA_PROJECT_MEMBERS" | tr ',' ' '); do
      _m=$(echo "$_m" | xargs); [ -n "$_m" ] || continue
      _ml=$(sca_user_lookup "$_m")
      if [ -n "$_ml" ]; then _resolved="${_resolved:+$_resolved }$(echo "$_ml" | cut -d'|' -f1)"
      else _missed="${_missed:+$_missed,}$_m"; fi
    done
    [ -n "$_missed" ] && warn "以下协作人在平台无同名用户，未加入项目成员: ${_missed}"
    if [ -n "$_resolved" ]; then
      _member_ids=$(echo "$_resolved" | tr ' ' '\n' | sort -un | paste -sd, -)
      log "项目成员解析成功: memberList=[${_member_ids}]"
    fi
  fi

  if [ -z "$FOUND" ]; then
    log "项目不存在，自动创建 (PM=${SCA_USERNAME:-令牌默认}${_owner_id:+/id:${_owner_id}}${_owner_dept:+, 部门=${_owner_dept}}${_member_ids:+, 成员=[${_member_ids}]})"
    # v2 报文: managerList/memberList/departmentId; 解析不到归属人时降级为仅项目名(老行为)
    _created=0
    if [ "$HAVE_JQ" = "1" ] && { [ -n "$_owner_id" ] || [ -n "$_member_ids" ]; }; then
      _create_body=$(jq -n --arg n "$SCA_PROJECT_NAME" --arg d "CI auto-provisioned;${SEC_META:-}" \
        --argjson mids "[${_member_ids:-}]" \
        --argjson oids "[${_owner_id:-}]" \
        --argjson dept "${_owner_dept:-0}" \
        '{name:$n, description:$d} + (if ($oids|length)>0 then {managerList:$oids} else {} end)
          + (if ($mids|length)>0 then {memberList:$mids} else {} end)
          + (if $dept>0 then {departmentId:$dept} else {} end)')
      resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" \
        -H "OpenApiUserToken: ${SCA_USER_TOKEN}" -d "${_create_body}" \
        "${API_ROOT}/openapi/v1/project/create")
      if echo "$resp" | jq -e '.code == 0' >/dev/null 2>&1; then
        _created=1; log "项目已创建(v2带归属: $(echo "$resp" | head -c 120))"
      else
        warn "v2创建未受理($(echo "$resp" | head -c 120)) → 降级为仅项目名创建"
      fi
    fi
    if [ "$_created" = "0" ]; then
      resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" \
        -H "OpenApiUserToken: ${SCA_USER_TOKEN}" \
        -d "{\"name\":\"${SCA_PROJECT_NAME}\"}" "${API_ROOT}/openapi/v1/project/create")
      echo "$resp" | jq -e '.code == 0' >/dev/null 2>&1 || die "创建失败: $(echo "$resp" | head -c 200)"
      log "项目已创建(按令牌默认归属)"
    fi
    sleep 2
    resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" \
      -H "OpenApiUserToken: ${SCA_USER_TOKEN}" \
      -d "{\"nameOrDescription\":\"${SCA_PROJECT_NAME}\"}" \
      "${API_ROOT}/openapi/v1/project/list")
    FOUND=$(echo "$resp" | jq -c --arg n "$SCA_PROJECT_NAME" \
      '.data.records[] | select(.name==$n) | {id, token}' 2>/dev/null | head -n1)
    [ -n "$FOUND" ] || die "创建后未查到项目（平台同步延迟，请重试）"
  else
    log "项目已存在，复用"
    # 已存在项目: 尝试同步成员/负责人(edit 幂等; 权限不足自动跳过)
    if [ "${SCA_PROJECT_SYNC_MEMBERS:-0}" = "1" ] && [ "$HAVE_JQ" = "1" ] \
       && { [ -n "$_owner_id" ] || [ -n "$_member_ids" ]; }; then
      _pid=$(echo "$FOUND" | jq -r '.id')
      _edit_body=$(jq -n --argjson pid "${_pid}" \
        --argjson mids "[${_member_ids:-}]" --argjson oids "[${_owner_id:-}]" \
        '{projectId:$pid} + (if ($oids|length)>0 then {managerList:$oids} else {} end)
          + (if ($mids|length)>0 then {memberList:$mids} else {} end)')
      _edit_resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" \
        -H "OpenApiUserToken: ${SCA_USER_TOKEN}" -d "${_edit_body}" \
        "${API_ROOT}/openapi/v1/project/edit")
      if echo "$_edit_resp" | jq -e '.code == 0' >/dev/null 2>&1; then
        log "项目成员/负责人已同步(edit)"
      else
        log "项目成员同步跳过(edit未受理: $(echo "$_edit_resp" | head -c 100))"
      fi
    fi
  fi
  SCA_PROJECT_ID=$(echo "$FOUND" | jq -r '.id')
  SCA_PROJECT_TOKEN=$(echo "$FOUND" | jq -r '.token')
  [ -n "$SCA_PROJECT_TOKEN" ] && [ "$SCA_PROJECT_TOKEN" != "null" ] || die "项目Token为空"
  export SCA_PROJECT_ID SCA_PROJECT_TOKEN
  cat > "$OUT_ENV_FILE" <<EOF
export SCA_PROJECT_ID="${SCA_PROJECT_ID}"
export SCA_PROJECT_TOKEN="${SCA_PROJECT_TOKEN}"
EOF
  log "项目就绪: id=${SCA_PROJECT_ID}（env: ${OUT_ENV_FILE}）"
}

# ============================================================================
# 【能力2】扫描核心（mode: deps=依赖特征文件 / artifact=制品SCAN_PATTERNS）
# ============================================================================
bypass_fail() { echo "$LOG_PREFIX $*" >&2; if [ "${BY_PASS:-1}" = "1" ]; then exit 0; else exit 3; fi; }

do_scan() {
  local mode="$1"
  [ -n "${SCA_URL:-}" ]         || die "scan: 请设置 SCA_URL"
  [ -n "${SCA_USER_TOKEN:-}" ]  || die "scan: 请设置 SCA_USER_TOKEN"
  [ -n "${SCA_PROJECT_TOKEN:-}" ] || die "scan: 请设置 SCA_PROJECT_TOKEN（先跑 provision 子命令或直接配置）"
  SCAN_DIR="${SCAN_DIR:-$PWD}"
  cd "$SCAN_DIR" || die "进入扫描目录失败: $SCAN_DIR"
  [ -n "${APP_NAME:-}" ] || APP_NAME="${SCA_PROJECT_NAME:-${REPO_IDENT:-scan-app}}-${GIT_BRANCH_NAME:-master}"
  case "$APP_NAME" in -|-master|-*'') APP_NAME="scan-app";; esac
  ARTIFACT_SUFFIX="${ARTIFACT_SUFFIX:--artifact}"
  [ "$mode" = "artifact" ] && APP_NAME="${APP_NAME}${ARTIFACT_SUFFIX}"

  # ---- 打包（依赖模式取平台特征正则 / 制品模式用自定义正则）----
  if [ "$mode" = "artifact" ]; then
    [ -n "${SCAN_PATTERNS:-}" ] || die "artifact 模式需设置 SCAN_PATTERNS"
    XMSCA_FILES="$SCAN_PATTERNS"
    log "制品扫描模式: $XMSCA_FILES"
  else
    log "获取平台特征文件类型 ..."
    types_resp=$(curl -s -k --max-time 60 -X GET \
      -H "OpenApiProjectToken: ${SCA_PROJECT_TOKEN}" -H "$AUTH_USER" \
      "${ROOT_FMT}/sca/api-v1/open-api-v1/upload/file/types")
    echo "$types_resp" | grep -q '"code":0' || bypass_fail "获取特征类型失败: $types_resp"
    if [ "$HAVE_JQ" = "1" ]; then XMSCA_FILES=$(echo "$types_resp" | jq -r '.data' 2>/dev/null)
    else XMSCA_FILES=$(field_str "$types_resp" data); fi
    [ -n "$XMSCA_FILES" ] && [ "$XMSCA_FILES" != "null" ] || die "特征文件类型解析失败"
  fi

  WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/sca.XXXXXX") || die "创建临时目录失败"
  trap 'rm -rf "$WORKDIR"' EXIT
  FILELIST="$WORKDIR/filelist"
  for fp in $XMSCA_FILES; do
    # 平台个别正则含 PCRE (?i)，POSIX ERE 不支持会告警——单模式静音跳过，不影响其余
    find . -type f 2>/dev/null | grep -E "$fp" >> "$FILELIST" 2>/dev/null || true
  done
  if [ ! -s "$FILELIST" ]; then
    log "未匹配到特征文件(${mode}模式), 跳过扫描"
    # 落盘说明性结果: 让聚合通知/下游明确知道"SCA跑了但无该类检测对象", 而不是疑惑为何缺数据
    if [ -n "${RESULT_JSON_FILE:-}" ]; then
      mkdir -p "$(dirname "$RESULT_JSON_FILE")" 2>/dev/null || true
      if [ "$HAVE_JQ" = "1" ]; then
        jq -n --arg app "${APP_NAME:-}" --arg mode "$mode" --arg branch "${GIT_BRANCH:-${GIT_BRANCH_NAME}}" \
          '{product:"sca", mode:$mode, appName:$app, branch:$branch, skipped:true,
            note:"未匹配到" + $mode + "模式特征文件(依赖清单/制品产物), 如需扫描请确认仓库包含对应文件或调整 SCAN_PATTERNS",
            scanTime:(now|todate)}' > "$RESULT_JSON_FILE" 2>/dev/null || true
      fi
    fi
    exit 0
  fi
  sort -u "$FILELIST" -o "$FILELIST"
  # 平台以 originName 作为应用名(实测2026-10-12): 统一用安全化的 APP_NAME, 不带扩展名
  # 注意用 printf(不带换行): echo 的行尾\n 会被 tr -c 替换成尾随 _(曾致应用名 xxx-main_.tar.gz)
  UPLOAD_ORIGIN="$(printf '%s' "${APP_NAME}" | tr -c 'A-Za-z0-9._-' '_')"
  PKG="$WORKDIR/${UPLOAD_ORIGIN}.tar.gz"
  tar zcf "$PKG" -T "$FILELIST" --ignore-failed-read 2>/dev/null || tar zcf "$PKG" -T "$FILELIST"
  PKG_SIZE=$(stat -f%z "$PKG" 2>/dev/null || stat -c%s "$PKG")
  PKG_MD5=$(md5_file "$PKG")
  log "打包完成: $(du -h "$PKG" | cut -f1)，开始分片上传 ..."

  # ---- 分片上传 ----
  split -b "${SPLIT_SIZE:-52428800}" "$PKG" "$PKG."
  slice_count=$(ls "$PKG".* 2>/dev/null | wc -l | tr -d ' ')
  asset_file_id=-1; idx=-1
  for slice in $(ls "$PKG".* 2>/dev/null); do
    idx=$((idx + 1))
    _up_ok=0
    for _up_try in 1 2; do
      resp=$(curl -s -k --max-time 300 -X POST -H "OpenApiUserToken: ${SCA_USER_TOKEN}" \
        -F "originName=${UPLOAD_ORIGIN}" -F "file=@${slice}" \
        "${ROOT_FMT}/sca/api-v1/open-api-v1/file/upload/slice?sliceByteSize=${SPLIT_SIZE:-52428800}&sliceTotal=${slice_count}&fileSize=${PKG_SIZE}&globalMd5=${PKG_MD5}&sliceIndex=${idx}&sliceTotal=${slice_count}")
      if echo "$resp" | grep -q '"code":0'; then _up_ok=1; break; fi
      [ $_up_try = 1 ] && { warn "分片${idx}上传失败, 5秒后重试: $(printf '%.80s' "$resp")"; sleep 5; }
    done
    [ "$_up_ok" = "1" ] || bypass_fail "分片${idx}上传失败(已重试): $resp"
    if [ "$HAVE_JQ" = "1" ]; then asset_file_id=$(echo "$resp" | jq -r '.data.uploaded.assetFileId // .data.assetFileId // .assetFileId' 2>/dev/null)
    else asset_file_id=$(field_num "$resp" assetFileId); fi
  done
  [ -n "$asset_file_id" ] && [ "$asset_file_id" != "-1" ] || bypass_fail "未获得 assetFileId"

  # ---- 提交任务 ----
  log "提交检测任务 ..."
  resp=$(curl -s -k --max-time 60 -X POST -H "OpenApiProjectToken: ${SCA_PROJECT_TOKEN}" \
    -H "$AUTH_USER" \
    "${ROOT_FMT}/sca/api-v1/open-api-v1/package/task/add2?clientType=${TASK_SOURCE:-9}&taskName=${APP_NAME}&dynamicDetect=${DYNAMIC_DETECT:-true}&similarity=${SIMILARITY:-false}&assetFileId=${asset_file_id}&effective=true&privateRepoIds=${PRIVATE_REPO_IDS:-}&description=$(printf '%s' "${SEC_META:-}" | sed 's/ /%20/g; s/;/%3B/g; s/=/%3D/g')")
  echo "$resp" | grep -q '"code":0' || bypass_fail "任务提交失败: $resp"
  TASK_ID=$(echo "$resp" | grep -Eo '"taskId":[0-9]+' | grep -Eo '[0-9]+')
  SCA_APP_ID=$(echo "$resp" | grep -Eo '"targetId":[0-9]+' | grep -Eo '[0-9]+')
  PROJECT_ID=$(echo "$resp" | grep -Eo '"projectId":[0-9]+' | grep -Eo '[0-9]+'); [ -n "$PROJECT_ID" ] || PROJECT_ID="${SCA_PROJECT_ID:-0}"
  SIGN=$(echo "$resp" | sed -n 's/.*"sign":"\([^"]*\)".*/\1/p')
  RESULT_URL="${SCA_URL}/open-page/${SCA_USER_TOKEN}/${SIGN}/cicd/${TASK_ID}/overview"
  log "任务已提交 taskId=${TASK_ID} 应用ID=${SCA_APP_ID}"
  log "结果页: ${RESULT_URL}"

  # ---- 轮询（1/2/3/12=进行中 5=完成）----
  start_ts=$(date +%s)
  while :; do
    sleep "${POLL_INTERVAL:-20}"
    resp=$(curl -s -k --max-time 60 -X GET -H "OpenApiProjectToken: ${SCA_PROJECT_TOKEN}" \
      -H "$AUTH_USER" "${ROOT_FMT}/sca/api-v1/open-api-v1/task/status/${TASK_ID}")
    echo "$resp" | grep -q '"code":0' || bypass_fail "查询任务状态失败: $resp"
    status=$(echo "$resp" | grep -Eo '"data":[0-9]+' | grep -Eo '[0-9]+')
    elapsed=$(( $(date +%s) - start_ts ))
    case "$status" in
      1|2|3|12) log "检测中... ${elapsed}s (状态=${status})" ;;
      5) log "检测完成 (耗时${elapsed}s)"; break ;;
      *) bypass_fail "检测任务异常(状态=${status})" ;;
    esac
    [ $(( elapsed / 60 )) -ge "${TIMEOUT_MINUTES:-90}" ] && bypass_fail "等待超过${TIMEOUT_MINUTES:-90}分钟"
  done

  # ---- 质量红线判定 ----
  GATE_ON=1; [ "$mode" = "artifact" ] && GATE_ON="${ARTIFACT_GATE:-1}" || GATE_ON="${DEPS_GATE:-1}"
  BLOCK="false"; GATE_RESULT="未启用"
  if [ "$GATE_ON" = "1" ]; then
    gbody="{\"sceneCode\":1,\"projectId\":${PROJECT_ID},\"taskId\":${TASK_ID}}"
    resp=$(curl -s -k --max-time 60 -X POST -H "Content-Type: application/json" \
      -H "engine-token: ${ENGINE_TOKEN:-XMTOKEN_0KFjl6SADaNA7WroFW9A}" \
      -d "$gbody" "${ROOT_FMT}/sca/api-v1/engine/rule/handle/rule")
    if echo "$resp" | grep -q '"code":0'; then
      BLOCK=$(echo "$resp" | grep -Eo '"block":(true|false)' | head -n1 | grep -Eo 'true|false')
      [ "$BLOCK" = "true" ] && GATE_RESULT="⛔ 不通过(命中质量红线)" || GATE_RESULT="✅ 通过"
      if [ "$BLOCK" = "true" ]; then
        lr=$(curl -s -k --max-time 60 -X GET -H "$AUTH_USER" \
          "${ROOT_FMT}/sca/api-v1/open-api-v1/getLogDetailByLogId/${TASK_ID}")
        if [ "$HAVE_JQ" = "1" ]; then GATE_DETAIL=$(echo "$lr" | jq -r '.data' 2>/dev/null | head -c 1200)
        else GATE_DETAIL=$(field_str "$lr" data | head -c 1200); fi
      fi
    else
      warn "红线判定接口异常: $resp"; GATE_RESULT="判定异常"
    fi
  fi

  echo "======================================================"
  echo "  源鉴SCA ${mode} 扫描结果  taskId=${TASK_ID}  app=${APP_NAME}"
  echo "  质量红线: ${GATE_RESULT}"
  echo "  结果页: ${RESULT_URL}"
  echo "======================================================"
  [ -n "${GATE_DETAIL:-}" ] && echo "---- 红线明细 ----" && echo "$GATE_DETAIL"

  # ---- 任务统计(组件/漏洞计数, 供通知卡片与下游消费; 平台聚合滞后约30-60s, 就绪即断) ----
  STAT_JSON=""
  if command -v curl >/dev/null 2>&1; then
    for _try in $(seq 1 15); do
      _stat=$(curl -s -k --max-time 30 -H "OpenApiUserToken: ${SCA_USER_TOKEN}" \
        "${API_ROOT}/openapi/v1/task/${TASK_ID}" 2>/dev/null)
      if echo "$_stat" | grep -q '"code":0'; then
        STAT_JSON=$(echo "$_stat" | jq -c '{componentNum, componentSeriousNum, componentHighNum, componentMediumNum, componentLowNum, componentNormalNum, vulNum, vulSeriousNum, vulHighNum, vulMediumNum, vulLowNum, licenseNum, licenseHighNum, licenseMediumNum, licenseLowNum} | with_entries(select(.value!=null))' 2>/dev/null)
        # vulNum 到位即认为统计已聚合完成
        [ "$(echo "$STAT_JSON" | jq -r '.vulNum // empty' 2>/dev/null)" != "" ] && break
      fi
      sleep 10
    done
    if [ "$(echo "$STAT_JSON" | jq -r '.vulNum // empty' 2>/dev/null)" != "" ]; then
      log "任务统计: 组件$(echo "$STAT_JSON"|jq -r '.componentNum')(🔴$(echo "$STAT_JSON"|jq -r '.componentSeriousNum // 0')/🟠$(echo "$STAT_JSON"|jq -r '.componentHighNum // 0')/🟡$(echo "$STAT_JSON"|jq -r '.componentMediumNum // 0')) 漏洞$(echo "$STAT_JSON"|jq -r '.vulNum')(严重$(echo "$STAT_JSON"|jq -r '.vulSeriousNum // 0')/高$(echo "$STAT_JSON"|jq -r '.vulHighNum // 0')/中$(echo "$STAT_JSON"|jq -r '.vulMediumNum // 0')/低$(echo "$STAT_JSON"|jq -r '.vulLowNum // 0')) 许可证$(echo "$STAT_JSON"|jq -r '.licenseNum // 0')(高风险$(echo "$STAT_JSON"|jq -r '.licenseHighNum // 0'))"
    else
      warn "任务统计未就绪(跳过统计字段, 不影响扫描结论)"
      STAT_JSON=""
    fi
  fi

  # ---- 结果JSON落盘 ----
  STAT_JSON_ARG='{}'
  [ -n "$STAT_JSON" ] && STAT_JSON_ARG="$STAT_JSON"
  if [ -n "${RESULT_JSON_FILE:-}" ]; then
    mkdir -p "$(dirname "$RESULT_JSON_FILE")" 2>/dev/null || true
    if [ "$HAVE_JQ" = "1" ]; then
      jq -n --arg app "$APP_NAME" --arg tid "$TASK_ID" --arg appid "${SCA_APP_ID:-0}" \
        --arg gate "$GATE_RESULT" --arg url "$RESULT_URL" --arg block "$BLOCK" \
        --arg branch "${GIT_BRANCH:-${GIT_BRANCH_NAME}}" \
        --arg commit "${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo '')}" \
        --argjson stat "$STAT_JSON_ARG" \
        '{product:"sca", mode:"'"$mode"'", appName:$app, taskId:$tid, appId:$appid, gate:$gate,
          block:$block, resultUrl:$url, branch:$branch, commit:$commit, scanTime:(now|todate)} + $stat' \
        > "$RESULT_JSON_FILE" 2>/dev/null || true
    else
      printf '{"product":"sca","mode":"%s","appName":"%s","taskId":"%s","appId":"%s","gate":"%s","block":"%s","resultUrl":"%s"}\n' \
        "$mode" "$(json_esc "$APP_NAME")" "$TASK_ID" "${SCA_APP_ID:-0}" "$(json_esc "$GATE_RESULT")" "$BLOCK" "$(json_esc "$RESULT_URL")" \
        > "$RESULT_JSON_FILE" 2>/dev/null || true
    fi
    export SCA_APP_ID
  fi

  notify_send "源鉴SCA·${APP_NAME}" "$(printf '### 源鉴SCA检测结果\n**应用**: %s\n**质量红线**: %s\n**结果页**: %s' "$APP_NAME" "$GATE_RESULT" "$RESULT_URL")"

  # ---- SBOM+VEX 自动导出(v2): 扫描完成即产 SPDX/CSAF 产物并归档 ----
  if [ "${AUTO_SBOM:-1}" = "1" ] && [ "${mode}" = "deps" ] && [ -n "${SCA_APP_ID:-}" ]; then
    _sbom_sh="$(dirname "$0")/sca-sbom.sh"
    if [ -f "$_sbom_sh" ]; then
      log "自动导出 SBOM+VEX (SBOM_TYPES=${SBOM_TYPES:-spdx vex})..."
      if SCA_URL="$SCA_URL" SCA_USER_TOKEN="$SCA_USER_TOKEN" APP_NAME="$APP_NAME" \
         SCA_APP_ID="$SCA_APP_ID" OUT_DIR="${OUT_DIR:-./sec-results}" \
         TLS_INSECURE="${TLS_INSECURE:-1}" SBOM_TYPES="${SBOM_TYPES:-spdx vex}" \
         bash "$_sbom_sh"; then
        log "SBOM/VEX 产物已就绪(见 ${OUT_DIR:-./sec-results})"
      else
        warn "SBOM/VEX 导出失败(不影响扫描结论, 可稍后在平台报告中心手动导出)"
      fi
    else
      warn "未找到同级 sca-sbom.sh，跳过 SBOM/VEX 自动导出"
    fi
  fi

  [ "$BLOCK" = "true" ] && { echo "$LOG_PREFIX 质量红线不通过，流水线置红"; exit 1; }
  return 0
}

do_deps()     { do_scan deps; }
do_artifact() { do_scan artifact; }

# ============================================================================
# 【能力3】构建（Maven优先→gradle→npm→tar兜底；BUILD_CMD可覆盖）
# ============================================================================
do_build() {
  if [ -n "${BUILD_CMD:-}" ]; then
    bash -c "$BUILD_CMD" || echo "$LOG_PREFIX BUILD_CMD 返回非零，按现有产物继续"
  elif command -v mvn >/dev/null 2>&1 && [ -f pom.xml ]; then
    mvn -B -q package -DskipTests || mvn -B package -DskipTests || true
  elif [ -f build.gradle ] && command -v gradle >/dev/null 2>&1; then
    gradle build -x test || true
  elif [ -f package.json ] && command -v npm >/dev/null 2>&1; then
    npm install --no-audit --no-fund >/dev/null 2>&1 || true
  else
    tar zcf app-artifact.tar.gz --exclude=app-artifact.tar.gz --exclude=.git --exclude=sec-kit --exclude=sec-results . 2>/dev/null || true
    log "[模拟构建] 生成制品 app-artifact.tar.gz"
  fi
  ls -lh target/*.jar build/libs/*.jar dist/ app-artifact.tar.gz 2>/dev/null | head -5 || true
}

# ============================================================================
# 【能力4】报告生成+下载（notice/download 生成 → list 轮询 → batch 下载）
# ============================================================================
do_report() {
  [ -n "${SCA_URL:-}" ]        || die "report: 请设置 SCA_URL"
  SCA_APP_ID="${SCA_APP_ID:-}" ; [ -n "$SCA_APP_ID" ] || die "report: 请设置 SCA_APP_ID（扫描结果JSON的appId字段，或 all 流程自动获取）"

  # 报告链路（生成/查询/下载）实测用户Token直连可用（2026-09-18 验证：下载 zip 内含 xlsx）
  # 注：若偶发 401011（平台会话策略瞬时干扰），gen_try/下载段会自动重试
  [ -n "${APP_NAME:-}" ] || APP_NAME="scan-app"
  OUT_DIR="${OUT_DIR:-./sec-results}"; mkdir -p "$OUT_DIR"
  REPORT_NAME="${REPORT_NAME:-${APP_NAME}-report}"
  TEMPLATE_ID="${TEMPLATE_ID:-1}"            # 1=CI/CD流水线报告模板（默认）
  EXPORT_TYPE="${EXPORT_TYPE:-5}"            # 5=Excel（4=HTML 3=JSON 2=Word 1=PDF 12=TXT）
  LANG_CODE="${LANG_CODE:-zh_CN}"            # zh_CN=中文

  log "触发生成: 应用ID=${SCA_APP_ID} 模板=${TEMPLATE_ID:-1} 格式=${EXPORT_TYPE:-5} 语言=${LANG_CODE:-zh_CN}"
  # 形态A（客户环境实测）：扁平结构 + xmscaLanguage(hyphen) + applicationIdSet
  if [ "$HAVE_JQ" = "1" ]; then
    bodyA=$(jq -n --arg rn "${REPORT_NAME}" --arg lang "${XMSCA_LANG:-zh-CN}" \
      --argjson etl "[${EXPORT_TYPE:-5}]" --argjson tpl "${TEMPLATE_ID:-1}" --argjson apps "[${SCA_APP_ID}]" \
      '{reportName:$rn, xmscaLanguage:$lang, typeList:$etl, reportContentType:0, advancedSwitch:0, reportTemplateId:$tpl, applicationIdSet:$apps, source:5}')
    # 形态B（演示4.13实测）：嵌套 reportParam + language(zh_CN) + applicationIdList
    bodyB=$(jq -n --arg rn "${REPORT_NAME}" --arg lang "zh_CN" \
      --argjson tpl "${TEMPLATE_ID:-1}" --argjson tids "[${TASK_ID:-0}]" --argjson etl "[${EXPORT_TYPE:-5}]" \
      '{reportName:$rn, source:5, language:$lang, sync:false, reportParam:{reportTemplateId:$tpl, taskIdList:$tids, exportTypeList:$etl}}')
  else
    bodyA="{\"reportName\":\"$(json_esc "$REPORT_NAME")\",\"xmscaLanguage\":\"${XMSCA_LANG:-zh-CN}\",\"typeList\":[${EXPORT_TYPE:-5}],\"reportContentType\":0,\"advancedSwitch\":0,\"reportTemplateId\":${TEMPLATE_ID:-1},\"applicationIdSet\":[${SCA_APP_ID}],\"source\":5}"
    bodyB="{\"reportName\":\"$(json_esc "$REPORT_NAME")\",\"source\":5,\"language\":\"zh_CN\",\"sync\":false,\"reportParam\":{\"reportTemplateId\":${TEMPLATE_ID:-1},\"taskIdList\":[${TASK_ID:-0}],\"exportTypeList\":[${EXPORT_TYPE:-5}]}}"
  fi
  # 端点×形态 按序尝试（客户实测端点优先，演示实测端点兜底）
  GEN_EP1="${ROOT_FMT}/sca/api-v1/asset/report/application/sca/generate"   # 客户环境实测（较新版本）
  GEN_EP2="${ROOT_FMT}/sca/api-v1/report/generate/detection"               # 演示环境实测（4.13）
  gen_try() {  # gen_try <url> <body>——瞬时 401011 自动重试一次
    local r
    r=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" -d "$2" "$1")
    if echo "$r" | grep -q 401011; then
      warn "瞬时401011，重试一次..."; sleep 2
      r=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" -d "$2" "$1")
    fi
    echo "$r"
  }
  resp=$(gen_try "$GEN_EP1" "$bodyA");  echo "$resp" | grep -q '"code":0' && GEN_OK=1
  [ "${GEN_OK:-}" != "1" ] && { resp=$(gen_try "$GEN_EP2" "$bodyA"); echo "$resp" | grep -q '"code":0' && GEN_OK=1; }
  [ "${GEN_OK:-}" != "1" ] && { resp=$(gen_try "$GEN_EP2" "$bodyB"); echo "$resp" | grep -q '"code":0' && GEN_OK=1; }
  echo "$resp" | grep -q '"code":0' || die "生成受理失败(端点×形态均已尝试): $(echo "$resp" | head -c 150)"
  log "生成已受理（异步，Excel/中文）"

  # 轮询：平台会把报告改名为【应用报告】<名称>-<时间戳>，用 contains 匹配 + status==1 + type 含 5
  REPORT_ID=""
  start_ts=$(date +%s)
  while :; do
    sleep 5
    resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" \
      -d '{"pageNum":1,"pageSize":20}' "${ROOT_FMT}/sca/api-v1/asset/report/list")
    if [ "$HAVE_JQ" = "1" ]; then
      REPORT_ID=$(echo "$resp" | jq -r --arg rn "${REPORT_NAME}" --argjson et "${EXPORT_TYPE:-5}" \
        '.data.records[] | select(.name | contains($rn)) | select(.status==1) | select((.type // []) | index($et)) | .id' 2>/dev/null | head -n1)
    else
      REPORT_ID=$(echo "$resp" | tr '{' '\n' | grep "$REPORT_NAME" | grep -Eo '"id":[0-9]+' | grep -Eo '[0-9]+' | head -n1)
    fi
    [ -n "$REPORT_ID" ] && break
    elapsed=$(( $(date +%s) - start_ts ))
    log "生成中... ${elapsed}s"
    [ $elapsed -ge 300 ] && { echo "$LOG_PREFIX 生成超时(5分钟)"; exit 1; }
  done
  log "报告已生成: id=${REPORT_ID}"

  # 下载（zip 内含 xlsx + csv）→ 解包取 xlsx
  OUT_FILE="${OUT_DIR}/${REPORT_NAME}_excel.zip"
  curl -s -k --max-time 120 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" \
    -d "{\"idList\":[${REPORT_ID}]}" "${ROOT_FMT}/sca/api-v1/asset/report/downLoadReport/batch" -o "$OUT_FILE"
  file_type=$(file -b "$OUT_FILE" 2>/dev/null || echo unknown)
  # 瞬时 401011（平台会话策略干扰）→ 自动重试一次下载
  if head -c 300 "$OUT_FILE" 2>/dev/null | grep -q 401011; then
    warn "下载遇瞬时401011，自动重试..."
    sleep 2
    curl -s -k --max-time 120 -X POST -H "Content-Type: application/json" -H "$AUTH_USER" \
      -d "{\"idList\":[${REPORT_ID}]}" "${ROOT_FMT}/sca/api-v1/asset/report/downLoadReport/batch" -o "$OUT_FILE"
    file_type=$(file -b "$OUT_FILE" 2>/dev/null || echo unknown)
  fi
  echo "$file_type" | grep -qi "json" && { log "下载返回异常: $(head -c 150 "$OUT_FILE")"; exit 2; }

  # 解包 xlsx：python3 优先（原生支持中文文件名）→ unzip 回退 → 保留zip兜底
  XLSX_FILE=""
  if command -v python3 >/dev/null 2>&1; then
    XLSX_FILE=$(python3 -c "
import zipfile, os, sys
z = zipfile.ZipFile('$OUT_FILE')
xlsx = [n for n in z.namelist() if n.endswith('.xlsx')]
if xlsx:
    out = os.path.join('$OUT_DIR', os.path.basename(xlsx[0]))
    open(out, 'wb').write(z.open(xlsx[0]).read())
    print(out)
" 2>/dev/null)
    [ -z "$XLSX_FILE" ] && warn "python3 解包未产出 xlsx"
  fi
  if [ -z "$XLSX_FILE" ] && command -v unzip >/dev/null 2>&1; then
    warn "改用 unzip 解包（中文文件名在部分系统可能报 Illegal byte sequence）..."
    (cd "$OUT_DIR" && unzip -o "$(basename "$OUT_FILE")" "*.xlsx" >/dev/null 2>&1) \
      && XLSX_FILE=$(ls "${OUT_DIR}"/*.xlsx 2>/dev/null | head -n1)
  fi
  if [ -n "$XLSX_FILE" ] && [ -f "$XLSX_FILE" ]; then
    :
  else
    warn "解包失败——保留 zip 归档（zip 内含 xlsx，可手工解出；执行机建议安装 python3 或 unzip）"
    XLSX_FILE="$OUT_FILE"
  fi
  echo "$XLSX_FILE" > "${OUT_DIR}/latest-report-path.txt"
  notify_send "SCA报告·${APP_NAME}" "Excel报告已生成: ${REPORT_NAME}（中文）"
  return 0
}

do_upload() {
  [ -n "${PKG_URL:-}" ]   || die "upload: 请设置 PKG_URL"
  [ -n "${PKG_USER:-}" ]  || die "upload: 请设置 PKG_USER"
  [ -n "${PKG_PASS:-}" ]  || die "upload: 请设置 PKG_PASS"
  PACKAGE_FILE="${PACKAGE_FILE:-$(cat "${OUT_DIR:-./sec-results}/latest-report-path.txt" 2>/dev/null || echo '')}"
  [ -n "$PACKAGE_FILE" ] && [ -f "$PACKAGE_FILE" ] || die "upload: 请设置 PACKAGE_FILE（要上传的文件）"
  FILENAME=$(basename "$PACKAGE_FILE")
  # 非 ASCII 文件名（如【应用报告】….xlsx）上传前转安全名，避免制品库 URL 兼容问题
  case "$FILENAME" in
    *[!A-Za-z0-9._-]*)
      SAFE_NAME="sca-report-$(date +%Y%m%d%H%M%S).${FILENAME##*.}"
      cp "$PACKAGE_FILE" "$(dirname "$PACKAGE_FILE")/$SAFE_NAME"
      PACKAGE_FILE="$(dirname "$PACKAGE_FILE")/$SAFE_NAME"
      FILENAME="$SAFE_NAME"
      log "文件名已 ASCII 化: ${FILENAME}"
      ;;
  esac
  PKG_URL_BASE="${PKG_URL%/}"
  UPLOAD_URL="${PKG_URL_BASE}/${FILENAME}"
  DOWNLOAD_URL="${UPLOAD_URL}"

  log "上传 ${FILENAME} → ${PKG_URL_BASE}/"
  HTTP_CODE=$(curl -s -k --max-time 300 -u "${PKG_USER}:${PKG_PASS}" -T "$PACKAGE_FILE" \
    -o /tmp/pkg_upload_resp -w "%{http_code}" "${UPLOAD_URL}")
  case "$HTTP_CODE" in
    200|201|204) log "上传成功 (HTTP ${HTTP_CODE})" ;;
    401|403) die "认证失败(HTTP ${HTTP_CODE})：检查制品库账号/权限";;
    *) die "上传返回 HTTP ${HTTP_CODE}: $(head -c 200 /tmp/pkg_upload_resp)";;
  esac
  echo "------------------------------------------------------------"
  echo "报告已归档: ${FILENAME}"
  echo "报告下载地址: ${DOWNLOAD_URL}   （下载需制品库账号认证）"
  echo "下载命令: curl -k -u \"\${PKG_USER}:\${PKG_PASS}\" -O \"${DOWNLOAD_URL}\""
  echo "------------------------------------------------------------"
  echo "${DOWNLOAD_URL}" > "$(dirname "$PACKAGE_FILE")/download-url.txt" 2>/dev/null || true
  return 0
}

# ============================================================================
# 【编排】all = provision → deps → build → artifact → report → upload
# ============================================================================
do_all() {
  do_provision                                   # 导出 SCA_PROJECT_ID/TOKEN
  RESULT_JSON_FILE="${RESULT_JSON_FILE:-./sec-results/sca-result.json}"
  mkdir -p "$(dirname "$RESULT_JSON_FILE")"
  do_scan deps                                   # 依赖扫描（导出 SCA_APP_ID）
  do_build
  SCAN_PATTERNS="${SCAN_PATTERNS:-.*\.(jar|war|zip|tar\.gz)$}"
  SCAN_DIR="${SCAN_DIR:-$PWD}"
  RESULT_JSON_FILE="${RESULT_JSON_FILE%.json}-artifact.json"
  do_scan artifact                               # 制品扫描（APP_NAME 自动加 -artifact 后缀）
  if [ "${REPORT_ENABLED:-1}" = "1" ] && [ -n "${SCA_APP_ID:-}" ]; then
    do_report || warn "报告环节失败（不阻断）"
  fi
  if [ "${PKG_ENABLED:-1}" = "1" ] && [ -n "${PKG_URL:-}" ]; then
    PACKAGE_FILE="${PACKAGE_FILE:-$(cat "${OUT_DIR:-./sec-results}/latest-report-path.txt" 2>/dev/null || echo '')}"
    [ -n "$PACKAGE_FILE" ] && do_upload || warn "无报告文件可上传（跳过）"
  else
    log "制品库上传跳过（未配置 PKG_URL 或 PKG_ENABLED=0）"
  fi
  echo "======================================================"
  echo "  全流程结束 $(date '+%F %T')"
  echo "======================================================"
}

# ============================================================================
# 【能力6】Gitee 回写（读取结果JSON → commit 状态徽标 + MR 汇总评论）
# ============================================================================
do_writeback() {
  [ -n "${MR_TOKEN:-}" ]  || die "writeback: 请设置 MR_TOKEN"
  [ -n "${MR_OWNER:-}" ]  || die "writeback: 请设置 MR_OWNER"
  [ -n "${MR_REPO:-}" ]   || die "writeback: 请设置 MR_REPO"
  [ -n "${MR_SHA:-}" ]    || die "writeback: 请设置 MR_SHA (commit sha)"
  MR_API="${MR_API:-https://gitee.com}"
  RESULT_DIR="${RESULT_DIR:-./sec-results}"
  WRITE_MR_COMMENT="${WRITE_MR_COMMENT:-1}"
  command -v jq >/dev/null 2>&1 || die "writeback: 需要 jq"

  api() { local m="$1" p="$2" b="${3:-}"; local a=(-s -k --max-time 30 -X "$m" -H "Content-Type: application/json" "$MR_API$p?access_token=${MR_TOKEN}"); [ -n "$b" ] && a+=(-d "$b"); curl "${a[@]}"; }
  urlencode() { printf '%s' "$1" | jq -sRr '@uri'; }
  judge() { [ "$1" = "⛔ 不通过" ] && echo failure || echo success; }
  write_status() {
    local ctx="$1" st="$2" desc="$3" url="$4" body resp
    body=$(jq -n --arg st "$st" --arg u "$url" --arg d "$desc" --arg c "$ctx" '{state:$st,target_url:$u,description:$d,context:$c}')
    resp=$(api POST "/api/v5/repos/$(urlencode "$MR_OWNER")/$(urlencode "$MR_REPO")/statuses/$(urlencode "$MR_SHA")" "$body")
    echo "$resp" | grep -q '"state"' && log "commit状态已回写: ${ctx} → ${st}" || warn "commit状态回写失败(${ctx})"
  }
  SUMMARY_MD=""
  add_row() { SUMMARY_MD="${SUMMARY_MD}| ${1} | ${2} | ${3} | [查看](${4}) |
"; }
  rj() { [ -f "$1" ] && cat "$1" || echo "{}"; }

  J=$(rj "$RESULT_DIR/codeai-result.json")
  [ "$J" != "{}" ] && { CNT=$(echo "$J" | jq -r '.defectCount'); GATE=$(echo "$J" | jq -r '.gateResult'); STC=$(judge "$GATE")
    add_row "灵脉CodeAI(SAST)" "$(echo "$GATE"|grep -q 不通过 && echo '❌ 未通过' || echo '✅ 通过')" "超危$(echo "$CNT"|jq -r '.super//0')/高危$(echo "$CNT"|jq -r '.high//0')/中危$(echo "$CNT"|jq -r '.middle//0')/低危$(echo "$CNT"|jq -r '.low//0')" "$(echo "$J"|jq -r '.platformUrl')"; }
  J=$(rj "$RESULT_DIR/sca-result.json")
  [ "$J" != "{}" ] && { STS=$(judge "$(echo "$J"|jq -r '.gate')")
    add_row "源鉴SCA(依赖)" "$(echo "$J"|jq -r '.gate'|grep -q 不通过 && echo '❌ 未通过' || echo '✅ 通过')" "红线: $(echo "$J"|jq -r '.gate')" "$(echo "$J"|jq -r '.resultUrl')"; }
  J=$(rj "$RESULT_DIR/sca-result-artifact.json")
  [ "$J" != "{}" ] && { STA=$(judge "$(echo "$J"|jq -r '.gate')")
    add_row "源鉴SCA(制品)" "$(echo "$J"|jq -r '.gate'|grep -q 不通过 && echo '❌ 未通过' || echo '✅ 通过')" "红线: $(echo "$J"|jq -r '.gate')" "$(echo "$J"|jq -r '.resultUrl')"; }
  J=$(rj "$RESULT_DIR/iast-result.json")
  [ "$J" != "{}" ] && { STI=$(judge "$(echo "$J"|jq -r '.gate')"); V=$(echo "$J"|jq -r '.vulCount')
    add_row "灵脉IAST(运行时)" "$(echo "$J"|jq -r '.gate'|grep -q 不通过 && echo '❌ 未通过' || echo '✅ 通过')" "高危$(echo "$V"|jq -r '.high//0')/中危$(echo "$V"|jq -r '.mid//0')/低危$(echo "$V"|jq -r '.low//0')" "$(echo "$J"|jq -r '.platformUrl')"; }

  for pair in "codeai:security/codeai:$STC" "sca:security/sca:$STS" "sca-artifact:security/sca-artifact:$STA" "iast:security/iast:$STI"; do
    ctx=$(echo "$pair" | cut -d: -f2); st=$(echo "$pair" | cut -d: -f3)
    [ -n "$st" ] && write_status "$ctx" "$st" "安全检测$( [ "$st" = "success" ] && echo 通过 || echo 未通过 )" "$MR_API"
  done

  if [ "$WRITE_MR_COMMENT" = "1" ] && [ -n "$SUMMARY_MD" ]; then
    PR_NUM="${MR_PR_NUMBER:-}"
    if [ -z "$PR_NUM" ] && [ -n "${GIT_BRANCH:-}" ]; then
      pulls=$(api GET "/api/v5/repos/$(urlencode "$MR_OWNER")/$(urlencode "$MR_REPO")/pulls?state=open&head=$(urlencode "${MR_OWNER}:${GIT_BRANCH}")")
      PR_NUM=$(echo "$pulls" | jq -r '.[0].number' 2>/dev/null)
    fi
    if [ -n "$PR_NUM" ] && [ "$PR_NUM" != "null" ]; then
      BODY_MD="## 🛡️ DevSecOps 安全检测汇总

| 检测引擎 | 结论 | 摘要 | 详情 |
|---|---|---|---|
${SUMMARY_MD}
> commit: \`${MR_SHA}\`　分支: \`${GIT_BRANCH:-N/A}\`　时间: $(date '+%Y-%m-%d %H:%M:%S')"
      body=$(jq -n --arg b "$BODY_MD" '{body:$b}')
      resp=$(api POST "/api/v5/repos/$(urlencode "$MR_OWNER")/$(urlencode "$MR_REPO")/issues/$(urlencode "$PR_NUM")/comments" "$body")
      echo "$resp" | grep -q '"id"' && log "MR#${PR_NUM} 汇总评论已回写" || warn "MR评论回写失败"
    else
      log "未找到开放MR，跳过评论（仅回写commit状态）"
    fi
  fi
  log "Gitee 回写完成"
}

# ============================================================================
# 【分发】子命令
# ============================================================================
derive_repo_identity
derive_biz_identity
CMD="${1:-all}"
case "$CMD" in
  all)       do_all ;;
  provision) do_provision ;;
  deps)      do_deps ;;
  build)     do_build ;;
  artifact)  do_artifact ;;
  report)    do_report ;;
  upload)    do_upload ;;
  writeback) do_writeback ;;
  *) die "未知子命令: ${CMD}（可用: all|provision|deps|build|artifact|report|upload|writeback）";;
esac
