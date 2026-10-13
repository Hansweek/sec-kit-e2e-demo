#!/usr/bin/env bash

set -uo pipefail
set +e
LOG_PREFIX="[悬镜安全·2/3]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }

_gnorm() { case "${1:-}" in 1|true|True|TRUE|y|Y|yes) echo 1;; 0|false|False|FALSE|n|N|no) echo 0;; *) echo "";; esac; }
_gres()  { _c=$(_gnorm "${2:-}"); if [ -n "$_c" ]; then echo "$_c"; else _g=$(_gnorm "${1:-}"); [ -n "$_g" ] && echo "$_g" || echo 0; fi; }
export DEPS_GATE=$(_gres "${SECURITY_GATE:-}" "${SCA_DEPS_GATE:-}")
export ARTIFACT_GATE=$(_gres "${SECURITY_GATE:-}" "${SCA_ARTIFACT_GATE:-}")
GIT_BRANCH_NAME="${CI_COMMIT_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo master)}"
GIT_COMMIT_SHA="${CI_COMMIT_ID:-$(git rev-parse HEAD 2>/dev/null || echo '')}"
_repo_url=$(git config --get remote.origin.url 2>/dev/null || echo '')
REPO_NAME=$(basename "${_repo_url%.git}" 2>/dev/null); [ -n "$REPO_NAME" ] || REPO_NAME="${CI_REPOSITORY_NAME:-yunxiao-app}"
SAFE_BRANCH=$(printf '%s' "$GIT_BRANCH_NAME" | tr '/ ' '__')
APP_NAME="${REPO_NAME}-${SAFE_BRANCH}"
BUILD_URL="云效流水线 ${CI_PIPELINE_NAME:-} #${CI_BUILD_NUMBER:-}"
CI_PLATFORM=yunxiao
export SAST_URL="${SAST_URL:-}" SAST_TOKEN="${SAST_TOKEN:-}" SAST_USERNAME="${SAST_USERNAME:-}"
export SCA_URL="${SCA_URL:-}" SCA_USER_TOKEN="${SCA_USER_TOKEN:-}"
export SCA_USERNAME="${SCA_USERNAME:-${SAST_USERNAME:-}}"
export SAST_PROJECT_NAME="${SAST_PROJECT_NAME:-$REPO_NAME}"
export SCA_PROJECT_NAME="${SCA_PROJECT_NAME:-$REPO_NAME}"
export SAST_PROJECT_MEMBERS="${SAST_PROJECT_MEMBERS:-${PROJECT_MEMBERS:-}}"
export SCA_PROJECT_MEMBERS="${SCA_PROJECT_MEMBERS:-${PROJECT_MEMBERS:-}}"
export SCA_PROJECT_SYNC_MEMBERS="${SCA_PROJECT_SYNC_MEMBERS:-0}"
export SKU_ID="${SKU_ID:-}" BIZ_LINE="${BIZ_LINE:-}"
export BY_PASS="${BY_PASS:-1}" BY_PASS_TIMEOUT_MINUTES="${BY_PASS_TIMEOUT_MINUTES:-60}" TIMEOUT_MINUTES="${TIMEOUT_MINUTES:-90}"
export TLS_INSECURE="${TLS_INSECURE:-0}" AUTO_SBOM="${AUTO_SBOM:-1}" SBOM_TYPES="${SBOM_TYPES:-spdx vex}"
export SAST_REPORT_KIND="${SAST_REPORT_KIND:-DEFECT}" EXPORT_DEFECTS="${EXPORT_DEFECTS:-1}"
GIT_TOP=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
SEC_ROOT="${WORK_SPACE:-$( [ -n "$GIT_TOP" ] && dirname "$GIT_TOP" || echo "$PWD" )}/sec-results"
export SEC_ROOT
mkdir -p "$SEC_ROOT"
log "仓库=$REPO_NAME 分支=$GIT_BRANCH_NAME 应用=$APP_NAME"

for c in curl jq; do command -v "$c" >/dev/null 2>&1 || { echo "$LOG_PREFIX [错误] 构建环境缺少 $c"; exit 2; }; done
ENGINE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xmir2.XXXXXX")"
trap 'rm -rf "$ENGINE_DIR"' EXIT
log "解包SCA引擎..."
cat > "$ENGINE_DIR/sca.sh" << 'XMITR_SCA_EOF'
set -uo pipefail
set +e
LOG_PREFIX="[SCA]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }
die()  { echo "$LOG_PREFIX [错误] $*" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || die "缺少 curl"
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1
field_str() { echo "$1" | sed -n 's/.*"'"$2"'":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1; }
field_num() { echo "$1" | grep -Eo "\"$2\"[[:space:]]*:[[:space:]]*[0-9]+" | head -n1 | grep -Eo '[0-9]+$'; }
json_esc()  { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
md5_file()  { if command -v md5sum >/dev/null 2>&1; then md5sum -b "$1" | awk '{print $1}'; else md5 -q "$1"; fi; }
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
_derive_disabled() {
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
notify_send() {
local title="$1" body="$2" payload
payload=$(jq -n --arg t "$title" --arg c "$body" '{msgtype:"markdown",markdown:{title:$t,text:$c}}')
curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$NOTIFY_WEBHOOK" >/dev/null || true
}
sca_user_lookup() {  # sca_user_lookup <username> → 输出 "userId|departmentId" (空=未找到)
local u="$1" resp
[ -n "$u" ] || { echo ""; return; }
[ "$HAVE_JQ" = "1" ] || { echo ""; return; }
resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json"  -H "OpenApiUserToken: ${SCA_USER_TOKEN}"  -d "{\"nameList\":[\"${u}\"]}" "${API_ROOT}/openapi/v1/user/list")
echo "$resp" | jq -r --arg u "$u"  '[.data.records[]? | select(.username==$u)] | if length>0 then (.[0] | "\(.userId)|\(.departmentId // 0)") else "" end' 2>/dev/null
}
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
resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json"  -H "OpenApiUserToken: ${SCA_USER_TOKEN}"  -d "{\"nameOrDescription\":\"${SCA_PROJECT_NAME}\"}"  "${API_ROOT}/openapi/v1/project/list")
echo "$resp" | jq -e '.code == 0' >/dev/null 2>&1 || die "项目查询失败: $(echo "$resp" | head -c 200)"
FOUND=$(echo "$resp" | jq -c --arg n "$SCA_PROJECT_NAME"  '.data.records[] | select(.name==$n) | {id, token}' 2>/dev/null | head -n1)
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
_created=0
if [ "$HAVE_JQ" = "1" ] && { [ -n "$_owner_id" ] || [ -n "$_member_ids" ]; }; then
_create_body=$(jq -n --arg n "$SCA_PROJECT_NAME" --arg d "CI auto-provisioned;${SEC_META:-}"  --argjson mids "[${_member_ids:-}]"  --argjson oids "[${_owner_id:-}]"  --argjson dept "${_owner_dept:-0}"  '{name:$n, description:$d} + (if ($oids|length)>0 then {managerList:$oids} else {} end)
+ (if ($mids|length)>0 then {memberList:$mids} else {} end)
+ (if $dept>0 then {departmentId:$dept} else {} end)')
resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json"  -H "OpenApiUserToken: ${SCA_USER_TOKEN}" -d "${_create_body}"  "${API_ROOT}/openapi/v1/project/create")
if echo "$resp" | jq -e '.code == 0' >/dev/null 2>&1; then
_created=1; log "项目已创建(v2带归属: $(echo "$resp" | head -c 120))"
else
warn "v2创建未受理($(echo "$resp" | head -c 120)) → 降级为仅项目名创建"
fi
fi
if [ "$_created" = "0" ]; then
resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json"  -H "OpenApiUserToken: ${SCA_USER_TOKEN}"  -d "{\"name\":\"${SCA_PROJECT_NAME}\"}" "${API_ROOT}/openapi/v1/project/create")
echo "$resp" | jq -e '.code == 0' >/dev/null 2>&1 || die "创建失败: $(echo "$resp" | head -c 200)"
log "项目已创建(按令牌默认归属)"
fi
sleep 2
resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json"  -H "OpenApiUserToken: ${SCA_USER_TOKEN}"  -d "{\"nameOrDescription\":\"${SCA_PROJECT_NAME}\"}"  "${API_ROOT}/openapi/v1/project/list")
FOUND=$(echo "$resp" | jq -c --arg n "$SCA_PROJECT_NAME"  '.data.records[] | select(.name==$n) | {id, token}' 2>/dev/null | head -n1)
[ -n "$FOUND" ] || die "创建后未查到项目（平台同步延迟，请重试）"
else
log "项目已存在，复用"
if [ "${SCA_PROJECT_SYNC_MEMBERS:-0}" = "1" ] && [ "$HAVE_JQ" = "1" ]  && { [ -n "$_owner_id" ] || [ -n "$_member_ids" ]; }; then
_pid=$(echo "$FOUND" | jq -r '.id')
_edit_body=$(jq -n --argjson pid "${_pid}"  --argjson mids "[${_member_ids:-}]" --argjson oids "[${_owner_id:-}]"  '{projectId:$pid} + (if ($oids|length)>0 then {managerList:$oids} else {} end)
+ (if ($mids|length)>0 then {memberList:$mids} else {} end)')
_edit_resp=$(curl -s -k --max-time 30 -X POST -H "Content-Type: application/json"  -H "OpenApiUserToken: ${SCA_USER_TOKEN}" -d "${_edit_body}"  "${API_ROOT}/openapi/v1/project/edit")
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
if [ "$mode" = "artifact" ]; then
[ -n "${SCAN_PATTERNS:-}" ] || die "artifact 模式需设置 SCAN_PATTERNS"
XMSCA_FILES="$SCAN_PATTERNS"
log "制品扫描模式: $XMSCA_FILES"
else
log "获取平台特征文件类型 ..."
types_resp=$(curl -s -k --max-time 60 -X GET  -H "OpenApiProjectToken: ${SCA_PROJECT_TOKEN}" -H "$AUTH_USER"  "${ROOT_FMT}/sca/api-v1/open-api-v1/upload/file/types")
echo "$types_resp" | grep -q '"code":0' || bypass_fail "获取特征类型失败: $types_resp"
if [ "$HAVE_JQ" = "1" ]; then XMSCA_FILES=$(echo "$types_resp" | jq -r '.data' 2>/dev/null)
else XMSCA_FILES=$(field_str "$types_resp" data); fi
[ -n "$XMSCA_FILES" ] && [ "$XMSCA_FILES" != "null" ] || die "特征文件类型解析失败"
fi
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/sca.XXXXXX") || die "创建临时目录失败"
trap 'rm -rf "$WORKDIR"' EXIT
FILELIST="$WORKDIR/filelist"
for fp in $XMSCA_FILES; do
find . -type f 2>/dev/null | grep -E "$fp" >> "$FILELIST" 2>/dev/null || true
done
if [ ! -s "$FILELIST" ]; then
log "未匹配到特征文件(${mode}模式), 跳过扫描"
if [ -n "${RESULT_JSON_FILE:-}" ]; then
mkdir -p "$(dirname "$RESULT_JSON_FILE")" 2>/dev/null || true
if [ "$HAVE_JQ" = "1" ]; then
jq -n --arg app "${APP_NAME:-}" --arg mode "$mode" --arg branch "${GIT_BRANCH:-${GIT_BRANCH_NAME}}"  '{product:"sca", mode:$mode, appName:$app, branch:$branch, skipped:true,
note:"未匹配到" + $mode + "模式特征文件(依赖清单/制品产物), 如需扫描请确认仓库包含对应文件或调整 SCAN_PATTERNS",
scanTime:(now|todate)}' > "$RESULT_JSON_FILE" 2>/dev/null || true
fi
fi
exit 0
fi
sort -u "$FILELIST" -o "$FILELIST"
UPLOAD_ORIGIN="$(printf '%s' "${APP_NAME}" | tr -c 'A-Za-z0-9._-' '_')"
PKG="$WORKDIR/${UPLOAD_ORIGIN}.tar.gz"
tar zcf "$PKG" -T "$FILELIST" --ignore-failed-read 2>/dev/null || tar zcf "$PKG" -T "$FILELIST"
PKG_SIZE=$(stat -f%z "$PKG" 2>/dev/null || stat -c%s "$PKG")
PKG_MD5=$(md5_file "$PKG")
log "打包完成: $(du -h "$PKG" | cut -f1)，开始分片上传 ..."
split -b "${SPLIT_SIZE:-52428800}" "$PKG" "$PKG."
slice_count=$(ls "$PKG".* 2>/dev/null | wc -l | tr -d ' ')
asset_file_id=-1; idx=-1
for slice in $(ls "$PKG".* 2>/dev/null); do
idx=$((idx + 1))
_up_ok=0
for _up_try in 1 2; do
resp=$(curl -s -k --max-time 300 -X POST -H "OpenApiUserToken: ${SCA_USER_TOKEN}"  -F "originName=${UPLOAD_ORIGIN}" -F "file=@${slice}"  "${ROOT_FMT}/sca/api-v1/open-api-v1/file/upload/slice?sliceByteSize=${SPLIT_SIZE:-52428800}&sliceTotal=${slice_count}&fileSize=${PKG_SIZE}&globalMd5=${PKG_MD5}&sliceIndex=${idx}&sliceTotal=${slice_count}")
if echo "$resp" | grep -q '"code":0'; then _up_ok=1; break; fi
[ $_up_try = 1 ] && { warn "分片${idx}上传失败, 5秒后重试: $(printf '%.80s' "$resp")"; sleep 5; }
done
[ "$_up_ok" = "1" ] || bypass_fail "分片${idx}上传失败(已重试): $resp"
if [ "$HAVE_JQ" = "1" ]; then asset_file_id=$(echo "$resp" | jq -r '.data.uploaded.assetFileId // .data.assetFileId // .assetFileId' 2>/dev/null)
else asset_file_id=$(field_num "$resp" assetFileId); fi
done
[ -n "$asset_file_id" ] && [ "$asset_file_id" != "-1" ] || bypass_fail "未获得 assetFileId"
log "提交检测任务 ..."
resp=$(curl -s -k --max-time 60 -X POST -H "OpenApiProjectToken: ${SCA_PROJECT_TOKEN}"  -H "$AUTH_USER"  "${ROOT_FMT}/sca/api-v1/open-api-v1/package/task/add2?clientType=${TASK_SOURCE:-9}&taskName=${APP_NAME}&dynamicDetect=${DYNAMIC_DETECT:-true}&similarity=${SIMILARITY:-false}&assetFileId=${asset_file_id}&effective=true&privateRepoIds=${PRIVATE_REPO_IDS:-}&description=$(printf '%s' "${SEC_META:-}" | sed 's/ /%20/g; s/;/%3B/g; s/=/%3D/g')")
echo "$resp" | grep -q '"code":0' || bypass_fail "任务提交失败: $resp"
TASK_ID=$(echo "$resp" | grep -Eo '"taskId":[0-9]+' | grep -Eo '[0-9]+')
SCA_APP_ID=$(echo "$resp" | grep -Eo '"targetId":[0-9]+' | grep -Eo '[0-9]+')
PROJECT_ID=$(echo "$resp" | grep -Eo '"projectId":[0-9]+' | grep -Eo '[0-9]+'); [ -n "$PROJECT_ID" ] || PROJECT_ID="${SCA_PROJECT_ID:-0}"
SIGN=$(echo "$resp" | sed -n 's/.*"sign":"\([^"]*\)".*/\1/p')
RESULT_URL="${SCA_URL}/open-page/${SCA_USER_TOKEN}/${SIGN}/cicd/${TASK_ID}/overview"
log "任务已提交 taskId=${TASK_ID} 应用ID=${SCA_APP_ID}"
log "结果页: ${RESULT_URL}"
start_ts=$(date +%s)
while :; do
sleep "${POLL_INTERVAL:-20}"
resp=$(curl -s -k --max-time 60 -X GET -H "OpenApiProjectToken: ${SCA_PROJECT_TOKEN}"  -H "$AUTH_USER" "${ROOT_FMT}/sca/api-v1/open-api-v1/task/status/${TASK_ID}")
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
GATE_ON=1; [ "$mode" = "artifact" ] && GATE_ON="${ARTIFACT_GATE:-1}" || GATE_ON="${DEPS_GATE:-1}"
BLOCK="false"; GATE_RESULT="未启用"
if [ "$GATE_ON" = "1" ]; then
gbody="{\"sceneCode\":1,\"projectId\":${PROJECT_ID},\"taskId\":${TASK_ID}}"
resp=$(curl -s -k --max-time 60 -X POST -H "Content-Type: application/json"  -H "engine-token: ${ENGINE_TOKEN:-XMTOKEN_0KFjl6SADaNA7WroFW9A}"  -d "$gbody" "${ROOT_FMT}/sca/api-v1/engine/rule/handle/rule")
if echo "$resp" | grep -q '"code":0'; then
BLOCK=$(echo "$resp" | grep -Eo '"block":(true|false)' | head -n1 | grep -Eo 'true|false')
[ "$BLOCK" = "true" ] && GATE_RESULT="⛔ 不通过(命中质量红线)" || GATE_RESULT="✅ 通过"
if [ "$BLOCK" = "true" ]; then
lr=$(curl -s -k --max-time 60 -X GET -H "$AUTH_USER"  "${ROOT_FMT}/sca/api-v1/open-api-v1/getLogDetailByLogId/${TASK_ID}")
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
STAT_JSON=""
if command -v curl >/dev/null 2>&1; then
for _try in $(seq 1 15); do
_stat=$(curl -s -k --max-time 30 -H "OpenApiUserToken: ${SCA_USER_TOKEN}"  "${API_ROOT}/openapi/v1/task/${TASK_ID}" 2>/dev/null)
if echo "$_stat" | grep -q '"code":0'; then
STAT_JSON=$(echo "$_stat" | jq -c '{componentNum, componentSeriousNum, componentHighNum, componentMediumNum, componentLowNum, componentNormalNum, vulNum, vulSeriousNum, vulHighNum, vulMediumNum, vulLowNum, licenseNum, licenseHighNum, licenseMediumNum, licenseLowNum} | with_entries(select(.value!=null))' 2>/dev/null)
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
STAT_JSON_ARG='{}'
[ -n "$STAT_JSON" ] && STAT_JSON_ARG="$STAT_JSON"
if [ -n "${RESULT_JSON_FILE:-}" ]; then
mkdir -p "$(dirname "$RESULT_JSON_FILE")" 2>/dev/null || true
if [ "$HAVE_JQ" = "1" ]; then
jq -n --arg app "$APP_NAME" --arg tid "$TASK_ID" --arg appid "${SCA_APP_ID:-0}"  --arg gate "$GATE_RESULT" --arg url "$RESULT_URL" --arg block "$BLOCK"  --arg branch "${GIT_BRANCH:-${GIT_BRANCH_NAME}}"  --arg commit "${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo '')}"  --argjson stat "$STAT_JSON_ARG"  '{product:"sca", mode:"'"$mode"'", appName:$app, taskId:$tid, appId:$appid, gate:$gate,
block:$block, resultUrl:$url, branch:$branch, commit:$commit, scanTime:(now|todate)} + $stat'  > "$RESULT_JSON_FILE" 2>/dev/null || true
else
printf '{"product":"sca","mode":"%s","appName":"%s","taskId":"%s","appId":"%s","gate":"%s","block":"%s","resultUrl":"%s"}\n'  "$mode" "$(json_esc "$APP_NAME")" "$TASK_ID" "${SCA_APP_ID:-0}" "$(json_esc "$GATE_RESULT")" "$BLOCK" "$(json_esc "$RESULT_URL")"  > "$RESULT_JSON_FILE" 2>/dev/null || true
fi
export SCA_APP_ID
fi
notify_send "源鉴SCA·${APP_NAME}" "$(printf '### 源鉴SCA检测结果\n**应用**: %s\n**质量红线**: %s\n**结果页**: %s' "$APP_NAME" "$GATE_RESULT" "$RESULT_URL")"
if [ "${AUTO_SBOM:-1}" = "1" ] && [ "${mode}" = "deps" ] && [ -n "${SCA_APP_ID:-}" ]; then
_sbom_sh="$(dirname "$0")/sca-sbom.sh"
if [ -f "$_sbom_sh" ]; then
log "自动导出 SBOM+VEX (SBOM_TYPES=${SBOM_TYPES:-spdx vex})..."
if SCA_URL="$SCA_URL" SCA_USER_TOKEN="$SCA_USER_TOKEN" APP_NAME="$APP_NAME"  SCA_APP_ID="$SCA_APP_ID" OUT_DIR="${OUT_DIR:-./sec-results}"  TLS_INSECURE="${TLS_INSECURE:-1}" SBOM_TYPES="${SBOM_TYPES:-spdx vex}"  bash "$_sbom_sh"; then
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
do_all() {
do_provision                                   # 导出 SCA_PROJECT_ID/TOKEN
RESULT_JSON_FILE="${RESULT_JSON_FILE:-./sec-results/sca-result.json}"
mkdir -p "$(dirname "$RESULT_JSON_FILE")"
do_scan deps                                   # 依赖扫描（导出 SCA_APP_ID）
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
XMITR_SCA_EOF
cat > "$ENGINE_DIR/sca-sbom.sh" << 'XMITR_SBOM_EOF'
set -uo pipefail
set +e
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
TRIGGERS=()
gen_sbom() {  # gen_sbom <sbomType> <fmt> <name>
local resp
resp=$(curl -s $TLS_FLAGS --max-time 60 -X POST -H "Content-Type: application/json" -H "$AUTH_USER"  -d "$(jq -n --argjson ids "[${SCA_APP_ID:-0}]" --arg rn "$3"  --argjson st "$1" --argjson sf "$2"  '{applicationIds:$ids, reportName:$rn, sbomFormat:$sf, sbomType:$st}')"  "$GEN_SBOM_EP")
if echo "$resp" | grep -q '"code":0'; then
log "SBOM 生成已受理: $3 (sbomType=$1)"; return 0
fi
warn "SBOM 生成未受理($3): $(echo "$resp" | head -c 150)"; return 1
}
gen_vex() {  # gen_vex <format> <name>
local resp
resp=$(curl -s $TLS_FLAGS --max-time 60 -X POST -H "Content-Type: application/json" -H "$AUTH_USER"  -d "$(jq -n --arg rn "$2" --argjson fmt "$1" --argjson ids "[${SCA_APP_ID:-0}]"  '{reportName:$rn, reportParam:{applicationIdList:$ids, format:$fmt}}')"  "$GEN_VEX_EP")
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
find_record() {  # find_record <显示名前缀(含【】)> → 输出 id
local want="$1" page=1 resp id total
while :; do
resp=$(curl -s $TLS_FLAGS --max-time 30 -X POST -H "Content-Type: application/json" -H "$AUTH_USER"  -d "{\"pageNum\":${page},\"pageSize\":50}" "$LIST_EP")
[ "$(echo "$resp" | jq -r '.code // -1' 2>/dev/null)" = "0" ] || return 1
id=$(echo "$resp" | jq -r --arg w "$want"  '.data.records[]? | select(.status==1) | select(.name | startswith($w)) | .id' 2>/dev/null | sort -n | tail -n1)
[ -n "$id" ] && [ "$id" != "null" ] && { echo "$id"; return 0; }
total=$(echo "$resp" | jq -r '.data.total // 0' 2>/dev/null); total=${total:-0}
[ $(( page * 50 )) -ge "$total" ] && return 1
page=$(( page + 1 ))
done
}
download_to() {  # download_to <recordId> <outfile>
local rid="$1" out="$2" attempt head
for attempt in 1 2; do
curl -s $TLS_FLAGS --max-time "$DL_TIMEOUT" -X POST -H "Content-Type: application/json" -H "$AUTH_USER"  -d "{\"idList\":[${rid}]}" "$DL_EP" -o "$out"
head=$(head -c 300 "$out" 2>/dev/null)
if echo "$head" | grep -q '"code"'; then
warn "下载返回平台错误(attempt=${attempt}): $(echo "$head" | head -c 120)"
elif head -c 1 "$out" 2>/dev/null | grep -qE '[{[]' &&  { [ ! -x "$(command -v python3)" ] || python3 -c "import json;json.load(open('$out'))" 2>/dev/null; }; then
return 0
fi
[ "$attempt" = "1" ] && { sleep 5; log "重试下载(可能传输截断)"; }
done
rm -f "$out"; return 1
}
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
pending=()
while IFS= read -r _p; do [ -n "$_p" ] && pending+=("$_p"); done <<< "$next"
[ "${#pending[@]}" -ge 1 ] || break
sleep 15; waited_total=$((waited_total + 15))
log "等待生成中... ${waited_total}s (剩余 ${#pending[@]} 项)"
done
if [ "${#pending[@]}" -ge 1 ]; then
for item in "${pending[@]}"; do warn "超时未生成: ${item%%|*}"; done
fi
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
jq -n --arg app "$APP_NAME" --argjson f "$FILES_JSON"  '{appName:$app, generatedAt:(now|todate), files:$f}' > "$RESULT_INFO_FILE"
log "产物清单已写入: ${RESULT_INFO_FILE}"
echo "SBOM_INFO_FILE=${RESULT_INFO_FILE}"
echo "SBOM_FILES=$(printf '%s ' ${OUT_SPDX:-} ${OUT_CDX:-} ${OUT_VEX:-})"
exit 0
fi
die "全部导出失败(见上方警告；也可稍后在平台 报告管理 手动导出)"
XMITR_SBOM_EOF
bash "$ENGINE_DIR/sca.sh" provision || exit 2
source ./provision.env
bash "$ENGINE_DIR/sca.sh" deps
if [ "${ENABLE_SCA_ARTIFACT:-0}" = "1" ] && [ -n "${SCAN_PATTERNS:-}" ]; then
export SCAN_PATTERNS ARTIFACT_GATE
RESULT_JSON_FILE="$SEC_ROOT/sca-result-artifact.json" bash "$ENGINE_DIR/sca.sh" artifact || true
fi
log "==== ③ 聚合通知（SAST+SCA 合并卡片） ===="
cat > "$ENGINE_DIR/notify.sh" << 'XMITR_NOTIFY_EOF'
set -uo pipefail
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
rj() { if [ -f "$1" ]; then cat "$1"; else echo '{}'; fi; }
SAST=$(rj "$RESULT_DIR/codeai-result.json")
SCA=$(rj "$RESULT_DIR/sca-result.json")
SCAA=$(rj "$RESULT_DIR/sca-result-artifact.json")
SBOM=$(rj "$RESULT_DIR/sbom-info.json")
has_any=0
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
if [ "$(echo "$SAST" | jq -r '.appName // empty' 2>/dev/null)" = "" ]  && [ -n "${SAST_URL:-}" ] && [ -n "${SAST_TOKEN:-}" ] && [ -n "${APP_NAME:-}" ]; then
_tl=""; [ "${TLS_INSECURE:-0}" = "1" ] && _tl="-k"
_pname=$(echo "$SAST" | jq -r '.projectName // empty' 2>/dev/null)
[ -z "$_pname" ] && _pname="${SAST_PROJECT_NAME:-${APP_NAME%-*}}"
_proj=$(curl -s $_tl --max-time 60 -G --url "${SAST_URL}/sast/api-v1/open-api/project/page"  --data-urlencode "pageNum=1" --data-urlencode "pageSize=50"  --header "Sast-Token: ${SAST_TOKEN}" 2>/dev/null)
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
SAST=$(jq -n --arg app "$APP_NAME" --argjson s "$sup" --argjson h "$high" --argjson m "$mid" --argjson l "$low"  --arg url "${SAST_URL}" --arg aid "$_app_id"  '{appName:$app, defectCount:{super:$s, high:$h, middle:$m, low:$l}, platformUrl:$url,
detailUrl:($url+"/detection/code/"+$aid+"/details/result"), gateResult:"未启用(仅告警)", scanMode:"平台最新"}')
fi
fi
if [ "$(echo "$SCA" | jq -r '.vulNum // empty' 2>/dev/null)" = "" ]  && [ "$(echo "$SCA" | jq -r '.taskId // empty' 2>/dev/null)" != "" ]  && [ -n "${SCA_URL:-}" ] && [ -n "${SCA_USER_TOKEN:-}" ] && command -v curl >/dev/null 2>&1; then
_tid=$(echo "$SCA" | jq -r '.taskId')
_api=$(echo "$SCA_URL" | sed 's/:30001/:30002/')
for _try in 1 2 3; do
_stat=$(curl -s -k --max-time 30 -H "OpenApiUserToken: ${SCA_USER_TOKEN}" "${_api}/openapi/v1/task/${_tid}" 2>/dev/null)
if echo "$_stat" | grep -q '"code":0'; then
_patch=$(echo "$_stat" | jq -c '{componentNum, componentSeriousNum, componentHighNum, componentMediumNum, componentLowNum, componentNormalNum, vulNum, vulSeriousNum, vulHighNum, vulMediumNum, vulLowNum, licenseNum, licenseHighNum, licenseMediumNum, licenseLowNum} | with_entries(select(.value!=null))' 2>/dev/null)
if [ "$(echo "$_patch" | jq -r '.vulNum // empty' 2>/dev/null)" != "" ]; then
SCA=$(echo "$SCA" | jq -c --argjson p "$_patch" '. + $p')
log "SCA 统计已补齐(vulNum=$(echo "$_patch" | jq -r '.vulNum'))"
break
fi
fi
[ "$_try" = "3" ] || { sleep 20; log "SCA 统计未就绪, 20秒后补查($_try/3)"; }
done
fi
verdict=""
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
if [ "$(echo "$SCAA" | jq -r '.appName // empty' 2>/dev/null)" != "" ]; then
has_any=1
aurl=$(echo "$SCAA" | jq -r '.resultUrl // ""')
av=$(echo "$SCAA" | jq -r '.vulNum // empty')
art_txt="**制品检测**（固件/产物成分）"
[ -n "$av" ] && art_txt="${art_txt}：漏洞 ${av}（🔴$(echo "$SCAA" | jq -r '.vulSeriousNum // 0') 🟠$(echo "$SCAA" | jq -r '.vulHighNum // 0')）"
[ -n "$aurl" ] && art_txt="${art_txt} ｜ [报告 →](${aurl})"
ART_LINE="$art_txt"
fi
SBOM_LINE=""
if [ "$(echo "$SBOM" | jq -r '.files // [] | length' 2>/dev/null)" != "0" ]; then
has_any=1
sbom_kinds=$(echo "$SBOM" | jq -r '.files | group_by(.desc)[] | (.[0].desc)' 2>/dev/null | sed 'N;s/\n/ ｜ /g')
SBOM_LINE="SBOM/VEX 产物已归档：${sbom_kinds}"
fi
[ "$has_any" = "1" ] || { log "sec-results/ 下无扫描结果，跳过通知"; exit 0; }
[ -n "$NOTIFY_WEBHOOK" ] || { log "未配置 NOTIFY_WEBHOOK，跳过推送(结果见流水线日志与产物)"; exit 0; }
[ -n "$verdict_tag" ] || verdict_tag="📋 检出摘要（门禁未启用）"
if [ "$verdict_tag" = "✅ 门禁通过" ]; then
_mixed=0
echo "$SAST" | jq -r '.gateResult // "未启用"' 2>/dev/null | grep -q "未启用" && _mixed=1
echo "$SCA"  | jq -r '.gate // "未启用"' 2>/dev/null    | grep -q "未启用" && _mixed=1
[ "$_mixed" = "1" ] && verdict_tag="✅ 门禁通过（部分门禁未启用）"
fi
TITLE="${NOTIFY_TITLE_PREFIX}｜${REPO_LABEL:-应用}${SKU_LABEL:+｜${SKU_LABEL}}"
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
_body_len=$(printf '%s' "$BODY" | wc -c | tr -d ' ')
if [ "$_body_len" -gt 18000 ]; then
warn "卡片内容${_body_len}字节超过钉钉上限, 截断保护(完整数据见流水线产物)"
BODY="$(printf '%.17000s' "$BODY")
> ⚠️ 内容过长已截断，完整缺陷清单与报告见下方链接"
fi
if [ "${NOTIFY_DRY_RUN:-0}" = "1" ]; then
echo "======== DRY RUN: TITLE ========"
echo "$TITLE"
echo "======== DRY RUN: BODY ========"
echo "$BODY"
exit 0
fi
at_now=0
[ "$verdict_tag" = "⛔ 门禁未通过" ] && at_now=1
[ "${NOTIFY_AT_ON_FAIL}" = "0" ] && [ -n "$NOTIFY_AT" ] && at_now=1
AT_LINE=""
[ "$at_now" = "1" ] && [ -n "$NOTIFY_AT" ] && AT_LINE=" @${NOTIFY_AT//,/ @}"
send_once() {
local url="$NOTIFY_WEBHOOK" payload resp
case "$NOTIFY_TYPE" in
dingtalk)
if [ -n "$NOTIFY_SECRET" ]; then
local ts sign
ts=$(date +%s000)
sign=$(printf '%s\n%s' "$ts" "$NOTIFY_SECRET"  | openssl dgst -sha256 -hmac "$NOTIFY_SECRET" -binary | base64)
url="${url}&timestamp=${ts}&sign=$(urlencode "$sign")"
fi
local at_mobiles="[]"
[ "$at_now" = "1" ] && [ -n "$NOTIFY_AT" ] && at_mobiles=$(echo "$NOTIFY_AT" | tr -d ' ' | jq -Rc 'split(",") | map(select(length>0))')
payload=$(jq -n --arg t "$TITLE" --arg b "${BODY}${AT_LINE}"  --argjson ats "$at_mobiles"  '{msgtype:"markdown",markdown:{title:$t,text:$b},
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
XMITR_NOTIFY_EOF
RESULT_DIR="$SEC_ROOT"  NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}" NOTIFY_TYPE="${NOTIFY_TYPE:-dingtalk}"  NOTIFY_SECRET="${NOTIFY_SECRET:-}" NOTIFY_AT="${NOTIFY_AT:-}"  NOTIFY_AT_ON_FAIL="${NOTIFY_AT_ON_FAIL:-1}" TLS_INSECURE="${TLS_INSECURE:-0}"  BUILD_URL="$BUILD_URL" REPO_LABEL="${REPO_NAME}"  SCA_URL="${SCA_URL:-}" SCA_USER_TOKEN="${SCA_USER_TOKEN:-}"  SAST_URL="${SAST_URL:-}" SAST_TOKEN="${SAST_TOKEN:-}"  SAST_PROJECT_NAME="${SAST_PROJECT_NAME:-$REPO_NAME}" APP_NAME="$APP_NAME"  TLS_INSECURE_SAST="${TLS_INSECURE:-0}"  bash "$ENGINE_DIR/notify.sh" || warn "聚合通知未确认送达(不影响扫描结论)"
exit 0

