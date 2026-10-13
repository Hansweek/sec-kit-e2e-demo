#!/usr/bin/env bash

set -uo pipefail
set +e
LOG_PREFIX="[悬镜安全·1/3]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }

_gnorm() { case "${1:-}" in 1|true|True|TRUE|y|Y|yes) echo 1;; 0|false|False|FALSE|n|N|no) echo 0;; *) echo "";; esac; }
_gres()  { _c=$(_gnorm "${2:-}"); if [ -n "$_c" ]; then echo "$_c"; else _g=$(_gnorm "${1:-}"); [ -n "$_g" ] && echo "$_g" || echo 0; fi; }
export GATE_ENABLED=$(_gres "${SECURITY_GATE:-}" "${SAST_GATE:-}")
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
export SAST_PROJECT_MEMBERS="${SAST_PROJECT_MEMBERS:-${PROJECT_MEMBERS:-}}"
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
log "诊断: PWD=$PWD WORK_SPACE=${WORK_SPACE:-未定义} GIT_TOP=${GIT_TOP:-未检出} SEC_ROOT=$SEC_ROOT"

for c in curl jq zip git; do command -v "$c" >/dev/null 2>&1 || { echo "$LOG_PREFIX [错误] 构建环境缺少 $c"; exit 2; }; done
command -v python3 >/dev/null 2>&1 || warn "缺少 python3: 全路径HTML导出降级(不影响扫描)"
export NOTIFY_WEBHOOK="" NOTIFY_SECRET="" NOTIFY_AT=""
set -uo pipefail
set +e
set -uo pipefail
set +e
set -uo pipefail
set +e
: "${SAST_URL:?请设置环境变量 SAST_URL (CodeAI平台地址，如 https://192.168.x.x，结尾不带/)}"
: "${SAST_TOKEN:?请设置环境变量 SAST_TOKEN (平台右上角头像→个人中心→访问令牌)}"
APP_NAME="${APP_NAME:-}"                  # 应用名；留空则自动取 仓库名-分支名。同名自动复用应用并延续增量基线
SAST_PROJECT_ID="${SAST_PROJECT_ID:-0}"   # 项目管理ID；0=不归入项目管理(快速检测)。配置后任务/应用挂到该项目下
SAST_PROJECT_NAME="${SAST_PROJECT_NAME:-}"  # 项目名称(与平台项目管理中的名称一致)；未配ID时按名称自动解析，平台无同名项目时自动创建
SAST_PROJECT_AUTO_CREATE="${SAST_PROJECT_AUTO_CREATE:-1}"  # 1=平台无同名项目时自动创建(实测接口); 0=只查找不创建
SAST_PROJECT_PM_ID="${SAST_PROJECT_PM_ID:-}"    # 项目经理用户ID。v2: 留空时自动取令牌归属人(需配 SAST_USERNAME)，再回退平台默认管理员=1
SAST_PROJECT_DEPT_ID="${SAST_PROJECT_DEPT_ID:-}"  # 归属部门ID。v2: 留空时自动取令牌归属人部门，再回退默认部门=1
SAST_USERNAME="${SAST_USERNAME:-}"        # 令牌归属人的平台用户名(个人中心可见)。用于自动解析 项目经理/归属部门(OpenAPI无whoami)
SAST_PROJECT_MEMBERS="${SAST_PROJECT_MEMBERS:-}"  # 仓库协作人平台用户名列表(逗号分隔,CI侧由 GitHub collaborators 映射注入)。
case "${SAST_PROJECT_ID}" in ''|*[!0-9]*) SAST_PROJECT_ID=0 ;; esac   # 防呆: 非数字(如误填项目名)回退快速检测
case "${SAST_PROJECT_PM_ID}" in ''|*[!0-9]*) SAST_PROJECT_PM_ID="" ;; esac
case "${SAST_PROJECT_DEPT_ID}" in ''|*[!0-9]*) SAST_PROJECT_DEPT_ID="" ;; esac
AUTO_LANGUAGE="${AUTO_LANGUAGE:-1}"       # 1=自动识别语言(推荐) 0=手动指定(需平台配模板)
SCAN_MODE="${SCAN_MODE:-2}"               # 1=快速扫描 2=深度扫描
TASK_SOURCE_TYPE="${TASK_SOURCE_TYPE:-3009}"  # 任务来源标签: 3001=Jenkins 3004=GitLab-CI 3009=通用Shell
SCAN_DIR="${SCAN_DIR:-$PWD}"              # 打包扫描的目录(默认当前目录=CI工作区)
EXCLUDES="${EXCLUDES:-.git sec-results node_modules target build dist .idea .vscode *.log *.zip}"
FORCE_FULL="${FORCE_FULL:-0}"             # 1=强制全量(定时巡检场景)；tag 发版自动全量，无需设置
CI_COMMIT_TAG="${CI_COMMIT_TAG:-}"        # CI 注入的 tag 名；非空=按发版全量处理
BY_PASS="${BY_PASS:-1}"                   # 1=平台排队超时自动放行，不卡流水线；0=严格模式一直等
BY_PASS_TIMEOUT_MINUTES="${BY_PASS_TIMEOUT_MINUTES:-60}"  # 共享平台建议≥60
HARD_TIMEOUT_MINUTES="${HARD_TIMEOUT_MINUTES:-180}"       # 绝对硬上限：BY_PASS=0 严格模式也不得死等
case "${BY_PASS_TIMEOUT_MINUTES}" in ''|*[!0-9]*) BY_PASS_TIMEOUT_MINUTES=60 ;; esac
case "${HARD_TIMEOUT_MINUTES}" in ''|*[!0-9]*) HARD_TIMEOUT_MINUTES=180 ;; esac
POLL_INTERVAL="${POLL_INTERVAL:-30}"      # 轮询间隔秒数
REPORT_DIR="${REPORT_DIR:-$SCAN_DIR}"     # PDF 报告落盘目录
RESULT_JSON_FILE="${RESULT_JSON_FILE:-}"  # 结构化结果JSON落盘路径(供下游消费，可留空)
SAST_REPORT_KIND="${SAST_REPORT_KIND:-DEFECT}"   # DEFECT=详情报告(默认,每缺陷类型全量条目) ANALYSE=概要报告
EXPORT_DIR="${EXPORT_DIR:-$SCAN_DIR/sec-results}"  # 全缺陷+跟踪路径导出目录(与SCA产物同目录,便于统一归档)
EXPORT_DEFECTS="${EXPORT_DEFECTS:-1}"       # 1=导出全缺陷+全跟踪路径(JSON+HTML) 0=关闭(大仓库赶时间时)
DEFECTS_PAGE_SIZE="${DEFECTS_PAGE_SIZE:-200}"     # defect/issue 分页大小(平台接受200,数量不限=自动翻页)
TRACE_CONCURRENCY="${TRACE_CONCURRENCY:-6}"       # 跟踪路径并发拉取数
GATE_ENABLED="${GATE_ENABLED:-0}"
GATE_SUPER="${GATE_SUPER:-0}"
GATE_HIGH="${GATE_HIGH:-0}"
GATE_MIDDLE="${GATE_MIDDLE:-0}"
GATE_LOW="${GATE_LOW:-0}"
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
NOTIFY_TYPE="${NOTIFY_TYPE:-dingtalk}"    # dingtalk | wecom | feishu | raw
NOTIFY_SECRET="${NOTIFY_SECRET:-}"        # 钉钉"加签"密钥/飞书签名密钥(未启用则留空)
NOTIFY_AT="${NOTIFY_AT:-}"                # 钉钉@手机号，逗号分隔
GIT_BRANCH="${GIT_BRANCH:-}"
GIT_COMMIT="${GIT_COMMIT:-}"
GIT_AUTHOR="${GIT_AUTHOR:-}"
BUILD_URL="${BUILD_URL:-}"
SCAN_TITLE="灵脉CodeAI代码安全扫描"
LOG_PREFIX="[CodeAI]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }
die()  { echo "$LOG_PREFIX [错误] $*" >&2; exit 2; }
for cmd in curl jq zip git; do
command -v "$cmd" >/dev/null 2>&1 || die "缺少命令 [$cmd]，请先安装: yum install -y curl jq zip 或 apt-get install -y curl jq zip"
done
sast_curl() {
local attempt resp rc
for attempt in 1 2 3; do
resp=$(curl -s $TLS_FLAGS --max-time 120 "$@"); rc=$?
if [ $rc -eq 0 ] && ! printf '%s' "$resp" | grep -qE '^[[:space:]]*$'; then
printf '%s' "$resp"; return 0
fi
[ $attempt -lt 3 ] && { warn "接口调用异常(rc=$rc${resp:+, $(printf '%.80s' "$resp")}), 5秒后重试($attempt/3)"; sleep 5; }
done
printf '%s' "$resp"; return $rc
}
sast_check_auth() {  # sast_check_auth <响应>
local code
code=$(printf '%s' "$1" | jq -r '.code // 0' 2>/dev/null)
case "$code" in
401) die "平台返回401: SAST_TOKEN 无效或已过期。请到 ${SAST_URL} 右上角头像→个人中心→访问令牌 重新生成, 并更新 CI Secrets/变量中的令牌" ;;
403) die "平台返回403: 当前令牌权限不足(需要项目管理/检测权限)。请联系平台管理员核对令牌归属账号的角色" ;;
esac
}
TLS_INSECURE="${TLS_INSECURE:-1}"
[ "$TLS_INSECURE" = "1" ] && TLS_FLAGS="-k" || TLS_FLAGS=""
sast_jq()   { echo "$1" | jq -r "$2" 2>/dev/null; }
urlencode() { printf '%s' "$1" | jq -sRr '@uri'; }
derive_biz_identity() {
SKU_ID="${SKU_ID:-}"
BIZ_LINE="${BIZ_LINE:-}"
if [ -z "$SKU_ID" ]; then
case "${GIT_BRANCH:-}" in
sku/*) SKU_ID="${GIT_BRANCH#sku/}" ;;
sku-*) SKU_ID="${GIT_BRANCH#sku-}" ;;
esac
fi
SEC_META="sec=kit;repo=${REPO_NAME:-};branch=${GIT_BRANCH:-}"
[ -n "$BIZ_LINE" ] && SEC_META="${SEC_META};biz=${BIZ_LINE}"
[ -n "$SKU_ID" ]   && SEC_META="${SEC_META};sku=${SKU_ID}"
[ -n "$SKU_ID" ] && log "业务标识: SKU=${SKU_ID}${BIZ_LINE:+ 品线=${BIZ_LINE}}(写入项目描述,平台可检索)"
}
validate_url_host() {
local u="$1" host
case "$u" in http://*|https://*) : ;; *) die "URL 必须以 http:// 或 https:// 开头: ${u:-空}" ;; esac
host=$(printf '%s' "$u" | sed -E 's#^[a-zA-Z]+://##; s#[/:?#].*$##')
case "$host" in
""|localhost|*.localhost|127.*|::1|[0:]*|0.0.0.0|169.254.*|metadata.*) die "拒绝访问本地/保留地址: $u" ;;
esac
case "$host" in
10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) log "使用内网平台地址(受支持的部署形态): ${host}" ;;
esac
}
validate_url_host "${SAST_URL}"
[ -z "${NOTIFY_WEBHOOK:-}" ] || validate_url_host "${NOTIFY_WEBHOOK}"
notify_send() {
local title="$1" body="$2"
[ -z "$NOTIFY_WEBHOOK" ] && { log "未配置 NOTIFY_WEBHOOK，跳过结果推送"; return 0; }
log "正在推送扫码结果到 $NOTIFY_TYPE ..."
case "$NOTIFY_TYPE" in
dingtalk)
local url="$NOTIFY_WEBHOOK"
if [ -n "$NOTIFY_SECRET" ]; then
local ts sign
ts=$(date +%s000)
sign=$(printf '%s\n%s' "$ts" "$NOTIFY_SECRET" \
| openssl dgst -sha256 -hmac "$NOTIFY_SECRET" -binary | base64)
url="${url}&timestamp=${ts}&sign=$(urlencode "$sign")"
fi
local at_text="" payload
[ -n "$NOTIFY_AT" ] && at_text=" @${NOTIFY_AT//,/ @}"
payload=$(jq -n --arg t "$title" --arg b "${body}${at_text}" \
--arg ats "$NOTIFY_AT" \
'{msgtype:"markdown",markdown:{title:$t,text:$b},
at:{atMobiles:($ats|split(",")|map(select(length>0))),isAtAll:false}}')
local resp
resp=$(curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$url")
log "钉钉推送返回: $resp" ;;
wecom)
local payload
payload=$(jq -n --arg c "$body" '{msgtype:"markdown",markdown:{content:$c}}')
local resp
resp=$(curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$NOTIFY_WEBHOOK")
log "企业微信推送返回: $resp" ;;
feishu)
local plain="★ ${body}"
plain=$(printf '%s' "$plain" | sed -e 's/^★ ### /★ /' -e 's/\*\*//g')
local payload extra=""
if [ -n "$NOTIFY_SECRET" ]; then
local ts sign
ts=$(date +%s)
sign=$(printf '%s\n%s' "$ts" "$NOTIFY_SECRET" \
| openssl dgst -sha256 -hmac "$NOTIFY_SECRET" -binary | base64)
extra=",\"timestamp\":\"${ts}\",\"sign\":\"${sign}\""
fi
payload=$(jq -n --arg t "$plain" "{msg_type:\"text\",content:{text:\$t}${extra}}")
local resp
resp=$(curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$NOTIFY_WEBHOOK")
log "飞书推送返回: $resp" ;;
raw)
local resp
resp=$(curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$RAW_RESULT_JSON" "$NOTIFY_WEBHOOK")
log "通用Webhook推送返回: $resp" ;;
*) warn "未知 NOTIFY_TYPE=$NOTIFY_TYPE，已跳过推送" ;;
esac
}
build_msg_body() {
local gate_line="$1"
cat <<EOF
**应用**: ${APP_NAME}
**分支/提交**: ${GIT_BRANCH:-N/A} / ${GIT_COMMIT:-N/A} ${GIT_AUTHOR:+by ${GIT_AUTHOR}}
**扫描方式**: ${SCAN_TYPE_DESC:-全量扫描}
**缺陷统计**: 超危 **${SUPER_COUNT:-0}** | 高危 **${HIGH_COUNT:-0}** | 中危 **${MIDDLE_COUNT:-0}** | 低危 **${LOW_COUNT:-0}**
**质量门禁**: ${gate_line}
**报告下载**: [平台查看/下载检测报告](${SAST_URL}/detection/code)（登录后按应用名 ${APP_NAME} 查看；PDF 已同步归档 CI 产物 sast_report.pdf）
**项目归属**: ${SAST_PROJECT_NAME:-快速检测}
EOF
}
log "==== 灵脉CodeAI 增量感知扫描开始 ===="
if [ -z "$APP_NAME" ]; then
_repo=$(basename -s .git "$(git -C "$SCAN_DIR" remote get-url origin 2>/dev/null || echo "$(basename "$SCAN_DIR")")")
_branch=$(git -C "$SCAN_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "default")
APP_NAME="${_repo}-${_branch}"
fi
SAFE_NAME=$(printf '%s' "$APP_NAME" | tr '/ ' '__')
[ -z "$GIT_BRANCH" ] && GIT_BRANCH=$(git -C "$SCAN_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "N/A")
[ -z "$GIT_COMMIT" ] && GIT_COMMIT=$(git -C "$SCAN_DIR" log -1 --format=%H 2>/dev/null || echo "N/A")
last_commit="$GIT_COMMIT"
REPO_NAME=$(printf '%s' "$APP_NAME" | sed 's/-[^-]*$//')
log "应用=${APP_NAME} 分支=${GIT_BRANCH} 提交=${last_commit}"
derive_biz_identity
PKG_FILE="${SCAN_DIR}/${SAFE_NAME}.zip"
rm -f "$PKG_FILE"
_avail_kb=$(df -k "$SCAN_DIR" 2>/dev/null | awk 'NR==2{print $4}')
[ -n "$_avail_kb" ] && [ "$_avail_kb" -lt 1048576 ] && warn "工作区剩余空间不足1GB(当前${_avail_kb}KB), 大仓库可能打包/落盘失败, 请清理后重试"
_x_args=()
for pat in $EXCLUDES; do _x_args+=(-x "$pat" -x "$pat/*" -x "*/$pat" -x "*/$pat/*"); done
( cd "$SCAN_DIR" && zip -rq "$PKG_FILE" . ${_x_args[@]+"${_x_args[@]}"} ) || die "源码打包失败"
log "源码已打包: ${PKG_FILE} ($(du -h "$PKG_FILE" | cut -f1))"
sast_user_page() {  # sast_user_page <username> → 输出 JSON行: userId|departmentId|nickname (空=未找到)
local u="$1" resp
[ -n "$u" ] || { echo ""; return; }
resp=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/system/user/page?username=$(urlencode "$u")&pageNum=1&pageSize=10" --header "Sast-Token: ${SAST_TOKEN}")
echo "$resp" | jq -r --arg u "$u" \
'[.data.records[]? // empty | select(.username==$u)] | if length>0 then (.[0] | "\(.userId)|\(.departmentId // 1)|\(.nickname // .username)") else "" end' 2>/dev/null
}
if [ "${SAST_PROJECT_ID:-0}" = "0" ] && [ -n "${SAST_PROJECT_NAME:-}" ]; then
log "按名称解析项目维度归属: ${SAST_PROJECT_NAME}"
if [ -z "$SAST_PROJECT_PM_ID" ] || [ -z "$SAST_PROJECT_DEPT_ID" ]; then
_owner=$(sast_user_page "${SAST_USERNAME}")
if [ -n "$_owner" ]; then
_o_uid=$(echo "$_owner" | cut -d'|' -f1); _o_dept=$(echo "$_owner" | cut -d'|' -f2); _o_name=$(echo "$_owner" | cut -d'|' -f3)
[ -z "$SAST_PROJECT_PM_ID" ]  && SAST_PROJECT_PM_ID="$_o_uid"
[ -z "$SAST_PROJECT_DEPT_ID" ] && SAST_PROJECT_DEPT_ID="$_o_dept"
log "令牌归属人 ${_o_name}: userId=${_o_uid} → 项目经理; 部门ID=${_o_dept} → 归属部门"
else
[ -n "${SAST_USERNAME}" ] && warn "SAST_USERNAME=${SAST_USERNAME} 在平台未匹配到用户，回退显式配置/默认值"
fi
fi
[ -z "$SAST_PROJECT_PM_ID" ]  && { SAST_PROJECT_PM_ID=1;  warn "未配置 SAST_USERNAME/SAST_PROJECT_PM_ID → 项目经理回退默认管理员(id=1)"; }
[ -z "$SAST_PROJECT_DEPT_ID" ] && { SAST_PROJECT_DEPT_ID=1; warn "未配置 SAST_USERNAME/SAST_PROJECT_DEPT_ID → 归属部门回退默认部门(id=1)"; }
_member_ids=""
if [ -n "${SAST_PROJECT_MEMBERS}" ]; then
_resolved=""; _missed=""
for _m in $(echo "$SAST_PROJECT_MEMBERS" | tr ',' ' '); do
_m=$(echo "$_m" | xargs); [ -n "$_m" ] || continue
_line=$(sast_user_page "$_m")
if [ -n "$_line" ]; then _resolved="${_resolved:+$_resolved }$(echo "$_line" | cut -d'|' -f1)"
else _missed="${_missed:+$_missed,}$_m"; fi
done
[ -n "$_missed" ] && warn "以下协作人在平台无同名用户，未加入项目成员(可在平台用户管理创建后手工加): ${_missed}"
if [ -n "$_resolved" ]; then
_member_ids=$(echo "$_resolved" | tr ' ' '\n' | sort -un | paste -sd, -)
log "项目成员解析成功: userIds=[${_member_ids}]"
fi
fi
_pm_page=1; _pm_id=""; _pm_retried=0
while [ -z "$_pm_id" ]; do
_pm_resp=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/project/page?pageNum=${_pm_page}&pageSize=50" --header "Sast-Token: ${SAST_TOKEN}")
[ "$(sast_jq "$_pm_resp" '.code')" = "0" ] || die "项目列表查询失败: ${_pm_resp}"
_pm_id=$(echo "$_pm_resp" | jq -r --arg n "${SAST_PROJECT_NAME}" '.data.records[]? | select(.projectName==$n) | .projectId' 2>/dev/null | head -n1)
if [ -z "$_pm_id" ] || [ "$_pm_id" = "null" ]; then
_pm_id=""
_pm_total=$(sast_jq "$_pm_resp" '.data.total'); _pm_total=${_pm_total:-0}; [ "$_pm_total" = "null" ] && _pm_total=0
if [ $(( _pm_page * 50 )) -ge "$_pm_total" ]; then
if [ "${SAST_PROJECT_AUTO_CREATE}" != "1" ]; then
die "平台项目管理中不存在名为[${SAST_PROJECT_NAME}]的项目, 且已关闭自动创建: 请先在平台创建, 或配 SAST_PROJECT_ID(数字)"
fi
if [ "${_pm_retried}" = "1" ]; then
die "项目[${SAST_PROJECT_NAME}]已存在但当前令牌不可见。处理: ①确认令牌归属账号与该项目一致(或配 SAST_USERNAME); ②平台把该项目授权给流水线账号; ③删除该项目后重跑流水线自动重建; ④直接配 SAST_PROJECT_ID=<项目数字ID>"
fi
log "平台无同名项目 → 自动创建项目 ${SAST_PROJECT_NAME} (PM=userId:${SAST_PROJECT_PM_ID}, 部门=${SAST_PROJECT_DEPT_ID}${_member_ids:+, 成员=[${_member_ids}]}) ..."
_pm_code=""; _pm_create=""
for _pm_try in 1 2; do
if [ "$_pm_try" = "1" ]; then
_pm_req=$(jq -n --arg n "${SAST_PROJECT_NAME}" \
--argjson pm "${SAST_PROJECT_PM_ID}" --argjson dept "${SAST_PROJECT_DEPT_ID}" \
--argjson mids "[${_member_ids:-}]" --arg meta "${SEC_META:-}" \
'{projectName:$n,pmId:$pm,departmentId:$dept}
+ (if ($mids|length)>0 then {userIds:$mids} else {} end)
+ (if ($meta|length)>0 then {description:$meta} else {} end)')
else
log "带成员创建被拒 → 降级为不带成员创建(成员稍后在平台 UI 添加)..."
_pm_req=$(jq -n --arg n "${SAST_PROJECT_NAME}" --argjson pm "${SAST_PROJECT_PM_ID}" --argjson dept "${SAST_PROJECT_DEPT_ID}" \
'{projectName:$n,pmId:$pm,departmentId:$dept}')
fi
_pm_create=$(sast_curl --request POST --url "${SAST_URL}/sast/api-v1/open-api/project/add" \
--header "Sast-Token: ${SAST_TOKEN}" --header "Content-Type: application/json" -d "${_pm_req}")
_pm_code=$(sast_jq "$_pm_create" '.code')
{ [ "$_pm_code" = "0" ] || [ "$_pm_code" = "1500014" ]; } && break
done
if [ "$_pm_code" = "1500014" ]; then
_pm_retried=1
log "平台提示项目名称已存在(1500014) → 重新解析项目ID..."
_pm_page=1
continue
fi
[ "$_pm_code" = "0" ] || die "项目自动创建失败: ${_pm_create}"
_pm_id=$(sast_jq "$_pm_create" '.data')
case "$_pm_id" in ""|"null") die "项目自动创建返回异常: ${_pm_create}" ;; esac
log "项目已自动创建 projectName=${SAST_PROJECT_NAME} projectId=${_pm_id}"
else
_pm_page=$(( _pm_page + 1 ))
fi
fi
done
SAST_PROJECT_ID="$_pm_id"
log "项目维度归属: ${SAST_PROJECT_NAME} → projectId=${SAST_PROJECT_ID}"
fi
app_existed=1
app_id=""
if [ "${SAST_PROJECT_ID:-0}" != "0" ]; then
list_resp=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/app/info/${SAST_PROJECT_ID}?appName=$(urlencode "${APP_NAME}")&pageNum=1&pageSize=50" --header "Sast-Token: ${SAST_TOKEN}")
app_id=$(echo "$list_resp" | jq -r --arg n "$APP_NAME"     '[.data.records[]? | select(.appName==$n) | (.appId|tostring)] | if length>0 then (max) else "" end' 2>/dev/null)
fi
if [ -z "$app_id" ] || [ "$app_id" = "null" ]; then
list_resp=$(sast_curl -G --url "${SAST_URL}/sast/api-v1/open-api/app/task/info" \
--data-urlencode "pageNum=1" --data-urlencode "pageSize=50" \
--data-urlencode "name=${APP_NAME}" --data-urlencode "isLike=true" \
--data-urlencode "scanningModes=1,2" --header "Sast-Token: ${SAST_TOKEN}")
app_id=$(echo "$list_resp" | jq -r --arg n "$APP_NAME" '.data.records[] | select(.taskName==$n) | .appId' 2>/dev/null | head -n1)
fi
if [ -z "$app_id" ] || [ "$app_id" = "null" ]; then
app_id=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/app/generate/id" --header "Sast-Token: ${SAST_TOKEN}" | jq -r '.data')
app_existed=0
log "新建应用 appId=${app_id}"
else
log "复用已有应用 appId=${app_id}"
fi
if [ -z "$app_id" ] || [ "$app_id" = "null" ]; then
sast_check_auth "${list_resp:-}"
die "appId 解析失败: 请检查 ①SAST_TOKEN 是否有效(个人中心→访问令牌) ②${SAST_URL} 从本执行机是否可达 ③平台版本是否支持该接口"
fi
increment=0
SCAN_TYPE_DESC="全量扫描"
DIFF_FILE="${SCAN_DIR}/${SAFE_NAME}.txt"
if [ "$FORCE_FULL" = "1" ]; then
log "强制全量(FORCE_FULL=1，定时巡检/手动指定)"
elif [ -n "$CI_COMMIT_TAG" ]; then
log "发版(tag=${CI_COMMIT_TAG})触发 → 全量扫描"
else
hash=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/app/git/hash/${app_id}" --header "Sast-Token: ${SAST_TOKEN}" | jq -r '.data')
echo "平台侧上次扫描 hash: ${hash}"
if [ "$hash" != "null" ] && [ -n "$hash" ]; then
git -C "$SCAN_DIR" diff --name-only "${hash}" "${last_commit}" > "$DIFF_FILE" || true
if [ -s "$DIFF_FILE" ]; then
log "存在变更文件 → 增量扫描"; cat "$DIFF_FILE"
increment=1
SCAN_TYPE_DESC="增量扫描(基线 ${hash} → ${last_commit})"
else
log "无文件变更 → 按全量提交"
fi
else
log "平台无扫描基线(首次) → 全量扫描"
fi
fi
[ -f "$DIFF_FILE" ] || echo "" > "$DIFF_FILE"
add_task_json=$(jq -n \
--arg app "${APP_NAME}" --arg appid "${app_id}" \
--argjson autolang "${AUTO_LANGUAGE}" --argjson apptype "1" \
--argjson projid "${SAST_PROJECT_ID}" --argjson src "${TASK_SOURCE_TYPE}" \
--argjson detmode "${SCAN_MODE}" \
'{repositoryType:0, appType:$apptype, projectId:$projid, appId:$appid,
appName:$app, autoLanguage:$autolang, appRuleList:[],
whiteMethodsSetsId:"0", fileFilterSetsId:"0",
taskSourceType:$src, detectionType:"1", scanningMode:$detmode,
taintSetsId:"0", sensitiveSetsId:"0", sensitiveSetsName:"",
taskConfig:{credibleSourceId:"0"}, description:""}')
if [ "${increment}" = "1" ]; then
add_task_json=$(echo "$add_task_json" | jq -c '. + {incrementSwitch:"1"}')
elif [ "${app_existed}" = "0" ]; then
add_task_json=$(echo "$add_task_json" | jq -c '. + {incrementSwitch:"0"}')
fi
curl_args=(-s $TLS_FLAGS --request POST --url "${SAST_URL}/sast/api-v1/open-api/app/saveOrAgainTask"
--header "Sast-Token: ${SAST_TOKEN}"
--header "content-type: multipart/form-data"
--form "file=@${PKG_FILE}"
--form "gitHash=${last_commit}"
--form "addTaskJson=${add_task_json}")
if [ "${increment}" = "1" ]; then
curl_args+=(--form "diff=@${DIFF_FILE}")
fi
response=$(curl "${curl_args[@]}")
log "接口返回: $response"
code=$(sast_jq "$response" '.code')
if [ "$code" = "0" ]; then
real_app_id=$(sast_jq "$response" '.data')
case "$real_app_id" in
""|"null")
real_app_id=""
log "任务已归并到已有应用 appId=${app_id}(平台未新建记录)"
;;
*)
log "任务提交成功 appId=${real_app_id}"
;;
esac
elif [ "$code" = "101104" ]; then
log "该应用上次任务仍在检测中(101104并发保护), 本流水线改为等待其结果"
elif [ "$code" = "101103" ]; then
die "任务提交失败(code=101103, 疑似引擎并发超限: License并发任务已满, 请错峰重试或评估扩容)"
else
die "任务提交失败(code=${code}，请检查令牌/包大小/平台状态)"
fi
poll_app="${real_app_id:-${app_id}}"
log "轮询应用 appId=${poll_app}"
status=0; taskId=0; start_time=$(date +%s); bypassed=0; anomaly=0
while [ "$status" != "3" ]; do
elapsed=$(( $(date +%s) - start_time ))
if [ "$BY_PASS" = "1" ] && [ $((elapsed / 60)) -ge "$BY_PASS_TIMEOUT_MINUTES" ]; then
log "排队超时(BY_PASS=${BY_PASS_TIMEOUT_MINUTES}分钟)，流水线放行，扫描在平台侧继续"
bypassed=1
break
fi
if [ $((elapsed / 60)) -ge "$HARD_TIMEOUT_MINUTES" ]; then
die "等待超过硬上限${HARD_TIMEOUT_MINUTES}分钟仍未完成(最后状态=${status:-空})，请登录平台查看任务"
fi
sleep "$POLL_INTERVAL"
response=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/defect/jenkins/result?appId=${poll_app}" --header "Sast-Token: ${SAST_TOKEN}")
rcode=$(sast_jq "$response" '.code')
if [ "$rcode" = "5003" ]; then log "任务尚未就绪(5003), 继续等待"; continue; fi
status=$(sast_jq "$response" '.data.status')
if [ "$rcode" != "0" ] || [ -z "$status" ] || [ "$status" = "null" ]; then
anomaly=$((anomaly + 1))
if [ "$anomaly" -ge 20 ]; then
die "平台连续${anomaly}轮返回异常(code=${rcode:-空}, status=${status:-空})，请检查 Sast-Token/网络/平台状态"
fi
warn "平台返回异常(code=${rcode:-空}, status=${status:-空})，第${anomaly}次重试"
continue
fi
anomaly=0
taskId=$(sast_jq "$response" '.data.taskId')
log "任务状态: ${status} (taskId=${taskId})"
case "$status" in
4|5|9)
if [ "$BY_PASS" = "1" ]; then
warn "平台任务异常终止 status=${status} (4=检测失败 5=已停止 9=已阻断)，按BY_PASS策略放行"
bypassed=1
break
fi
die "平台任务异常终止 status=${status} (4=检测失败 5=已停止 9=已阻断)"
;;
esac
done
if [ "$bypassed" = "1" ]; then
rm -f "$PKG_FILE"
SUPER_COUNT=0; HIGH_COUNT=0; MIDDLE_COUNT=0; LOW_COUNT=0
RAW_RESULT_JSON=""
GATE_RESULT="⏭ 放行(扫描未结束, 平台侧继续)"
MSG_BODY=$(build_msg_body "$GATE_RESULT")
notify_send "${SCAN_TITLE}·${APP_NAME}" "$MSG_BODY"
log "BY_PASS 放行退出(退出码0)。请稍后在平台查看 ${APP_NAME} 的扫描结果"
exit 0
fi
result_resp="$response"
SUPER_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].superCount] | add // 0')
HIGH_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].highCount] | add // 0')
MIDDLE_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].middleCount] | add // 0')
LOW_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].lowCount] | add // 0')
log "缺陷统计: 超危=${SUPER_COUNT} 高危=${HIGH_COUNT} 中危=${MIDDLE_COUNT} 低危=${LOW_COUNT}"
log "生成检测报告(类型=${SAST_REPORT_KIND}: DEFECT=详情报告, ANALYSE=概要报告)..."
enc_name=$(urlencode "${APP_NAME}")
report_pdf="${REPORT_DIR}/sast_report.pdf"
gen_report_via_common() {  # common 端点(支持 reportComponent) → 输出 reportId 或空
local resp rid
resp=$(sast_curl --request POST --url "${SAST_URL}/sast/api-v1/open-api/defect/common/generate/report" \
-H "Sast-Token: ${SAST_TOKEN}" -H "Content-Type: application/json" \
-d "$(jq -n --arg rc "${SAST_REPORT_KIND}" --arg rn "${APP_NAME}" \
--arg app "${poll_app}" --arg tid "${taskId}" \
'{reportType:1, reportName:$rn, appId:$app, taskId:$tid, reportComponent:$rc}')")
rid=$(sast_jq "$resp" '.data')
{ [ -n "$rid" ] && [ "$rid" != "null" ]; } || { warn "common端点未受理: $(echo "$resp" | head -c 150)"; echo ""; return; }
echo "$rid"
}
gen_report_via_blue() {  # 旧 blue 端点兜底(4.x) → 输出 reportId 或空
local resp rid
resp=$(sast_curl --request GET \
--url "${SAST_URL}/sast/api-v1/open-api/defect/blue/generate/report?reportType=1&taskId=${taskId}&reportName=${enc_name}&appId=${poll_app}" \
-H "Sast-Token: ${SAST_TOKEN}")
rid=$(sast_jq "$resp" '.data')
{ [ -n "$rid" ] && [ "$rid" != "null" ]; } || { warn "blue端点未受理: $(echo "$resp" | head -c 150)"; echo ""; return; }
echo "$rid"
}
REPORT_ID=$(gen_report_via_common)
[ -z "$REPORT_ID" ] && REPORT_ID=$(gen_report_via_blue)
if [ -z "$REPORT_ID" ]; then
warn "报告创建失败，跳过报告下载(可在平台 检测报告 页面手动生成)"
else
log "报告生成中 (reportId=${REPORT_ID})"
r_status=""; r_start=$(date +%s)
while [ "$r_status" != "2" ]; do
sleep 5
r_status=$(sast_curl --request GET \
--url "${SAST_URL}/sast/api-v1/open-api/defect/common/generate/report/status?reportId=${REPORT_ID}" \
-H "Sast-Token: ${SAST_TOKEN}" | jq -r '.data.status // 0' 2>/dev/null)
if [ $(( $(date +%s) - r_start )) -gt 600 ]; then warn "报告生成超时(10分钟，详情报告较大属正常，可稍后在平台下载)，跳过"; break; fi
done
if [ "$r_status" = "2" ]; then
sast_curl --request GET \
--url "${SAST_URL}/sast/api-v1/open-api/defect/common/download/report?reportId=${REPORT_ID}" \
-H "Sast-Token: ${SAST_TOKEN}" -o "$report_pdf"
if head -c 4 "$report_pdf" 2>/dev/null | grep -q "%PDF"; then
log "PDF报告已下载: ${report_pdf} ($(du -h "$report_pdf" | cut -f1))"
else
warn "common下载失败，尝试blue端点..."
sast_curl --request GET \
--url "${SAST_URL}/sast/api-v1/open-api/defect/blue/download/report?reportId=${REPORT_ID}" \
-H "Sast-Token: ${SAST_TOKEN}" -o "$report_pdf"
head -c 4 "$report_pdf" 2>/dev/null | grep -q "%PDF" && log "PDF报告已下载: ${report_pdf}" || warn "报告下载失败(保留平台侧报告记录)"
fi
elif [ "$r_status" = "3" ]; then
warn "平台报告生成失败(status=3)"
fi
fi
DEFECTS_JSON_FILE=""; DEFECTS_HTML_FILE=""
if [ "${EXPORT_DEFECTS}" = "1" ] && [ "${taskId}" != "0" ] && [ -n "${taskId}" ]; then
log "导出全缺陷清单+跟踪路径(供审计追溯, 与PDF报告同归档)..."
mkdir -p "$EXPORT_DIR"
DEFECTS_JSON_FILE="${EXPORT_DIR}/sast-defects-full.json"
DEFECTS_HTML_FILE="${EXPORT_DIR}/sast-defects-full.html"
_d_page=1; _d_all="/tmp/sast-defects-$$.jsonl"; : > "$_d_all"; _d_total=0
while :; do
_d_resp=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/defect/issue?taskId=${taskId}&isProblem=0&pageNum=${_d_page}&pageSize=${DEFECTS_PAGE_SIZE}" --header "Sast-Token: ${SAST_TOKEN}")
if [ "$(sast_jq "$_d_resp" '.code')" != "0" ]; then
warn "缺陷清单第${_d_page}页拉取失败: $(echo "$_d_resp" | head -c 120)"; break
fi
_d_cnt=$(echo "$_d_resp" | jq -r '.data.records | length' 2>/dev/null)
echo "$_d_resp" | jq -c '.data.records[]?' >> "$_d_all" 2>/dev/null
_d_total=$((_d_total + _d_cnt))
_d_sum=$(sast_jq "$_d_resp" '.data.total'); _d_sum=${_d_sum:-0}; [ "$_d_sum" = "null" ] && _d_sum=0
[ "$_d_cnt" -lt "${DEFECTS_PAGE_SIZE}" ] && break
[ "$_d_total" -ge "$_d_sum" ] && break
_d_page=$((_d_page + 1))
done
log "缺陷清单共 ${_d_total} 条，开始拉取跟踪路径(并发=${TRACE_CONCURRENCY})..."
_tr_dir="/tmp/sast-traces-$$"; mkdir -p "$_tr_dir"
export SAST_URL SAST_TOKEN TLS_FLAGS
_fetch_trace() {
local rid="$1" out="$2" resp
resp=$(curl -s $TLS_FLAGS --max-time 60 --url "${SAST_URL}/sast/api-v1/open-api/defect/risk/file/trace?riskFileIssueId=${rid}" --header "Sast-Token: ${SAST_TOKEN}")
echo "$resp" > "$out"
}
export -f _fetch_trace
jq -r '.riskIssueId' "$_d_all" 2>/dev/null | xargs -P "${TRACE_CONCURRENCY}" -I{} bash -c '_fetch_trace "$1" "${2}.json"' _ {} "${_tr_dir}/{}"
n=$(ls "$_tr_dir" 2>/dev/null | wc -l | tr -d ' ')
log "跟踪路径已获取 ${n}/${_d_total}"
DEFECTS_EXPORT_OK=0
if command -v python3 >/dev/null 2>&1; then
    python3 - "$_d_all" "$_tr_dir" "$DEFECTS_JSON_FILE" "$DEFECTS_HTML_FILE" "$APP_NAME" "$taskId" "$poll_app" "$SAST_URL" "$GIT_BRANCH" "$GIT_COMMIT" "$SCAN_TYPE_DESC" << 'PYEOF'
import json, sys, html, os, datetime
defects_file, trace_dir, out_json, out_html = sys.argv[1:5]
app, taskid, appid, base_url, branch, commit, scanmode = sys.argv[5:12]
defects=[json.loads(l) for l in open(defects_file) if l.strip()]
lvl={1:'超危',2:'高危',3:'中危',4:'低危'}
tt={0:'其他',1:'来源',2:'跟踪',3:'汇聚'}
for d in defects:
    tf=os.path.join(trace_dir, f"{d.get('riskIssueId')}.json")
    try:
        tr=json.load(open(tf))
        d['traces']=(tr.get('data') if isinstance(tr,dict) else tr) or []
    except Exception:
        d['traces']=[]
out={"meta":{"appName":app,"taskId":taskid,"appId":appid,"platformUrl":base_url,"branch":branch,
      "commit":commit,"scanMode":scanmode,"exportedAt":datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
      "defectTotal":len(defects),
      "note":"缺陷数量不限全量导出; traces=污点跟踪路径(数组,每条为一条完整链), traceType: 1来源 2跟踪 3汇聚"},
     "defects":sorted(defects, key=lambda x:(x.get('riskLevel',9), x.get('secondaryName','')))}
json.dump(out, open(out_json,'w'), ensure_ascii=False, indent=1)
cnt={}
for d in defects: cnt[d.get('riskLevel',9)]=cnt.get(d.get('riskLevel',9),0)+1
rows=[]
for d in out['defects']:
    tr_html=''
    for pi,path in enumerate(d.get('traces') or []):
        steps=''.join(
          f'<div class="step"><span class="tag t{n.get("traceType",0)}">{tt.get(n.get("traceType",0),"?")}</span>'
          f'<code>{html.escape(str(n.get("url","")))}</code>'
          f'<span class="line">:{n.get("line","")}</span>'
          f'<span class="txt">{html.escape(str(n.get("text","")))}</span></div>'
          for n in (path or []))
        tr_html+=f'<div class="path"><div class="pnum">路径 {pi+1}</div>{steps}</div>'
    if not tr_html: tr_html='<div class="path none">（该缺陷类型无污点跟踪链，风险点即缺陷点）</div>'
    rows.append(
      f'<tr><td>{html.escape(str(d.get("defectName") or d.get("ruleName") or ""))}</td>'
      f'<td>{html.escape(str(d.get("flawLocation") or d.get("fileName") or ""))}:{d.get("startLine","")}</td>'
      f'<td class="l{d.get("riskLevel",0)}">{lvl.get(d.get("riskLevel"),"-")}</td>'
      f'<td class="paths">{tr_html}</td></tr>')
summary=' '.join(f'<span class="s">{lvl.get(k,k)}: {v}</span>' for k,v in sorted(cnt.items()))
doc=f'''<!doctype html><html lang=zh><head><meta charset=utf-8><title>{html.escape(app)} 全缺陷跟踪报告</title>
<style>
body{{font-family:"Microsoft YaHei",Arial,sans-serif;color:#222;margin:24px;background:#fff}}
h1{{font-size:18px;border-bottom:2px solid #333;padding-bottom:8px}}
.meta{{color:#555;font-size:12px;margin:8px 0 16px;line-height:1.8}}
table{{border-collapse:collapse;width:100%;font-size:12px}}
th{{background:#f0f0f0;border:1px solid #999;padding:6px 8px;text-align:left}}
td{{border:1px solid #bbb;padding:6px 8px;vertical-align:top}}
.l1{{color:#c00;font-weight:bold}}.l2{{color:#e60;font-weight:bold}}.l3{{color:#a80}}.l4{{color:#888}}
.path{{margin:4px 0 10px;padding:6px;border-left:3px solid #999;background:#fafafa}}
.path.none{{color:#888}}
.pnum{{font-weight:bold;margin-bottom:4px;font-size:11px}}
.step{{margin:2px 0;line-height:1.6}}
.tag{{display:inline-block;border:1px solid #888;border-radius:2px;font-size:11px;padding:0 4px;margin-right:6px;background:#eee}}
.t1{{background:#c00;color:#fff;border-color:#c00}}.t3{{background:#333;color:#fff;border-color:#333}}
code{{background:#f5f5f5;padding:0 3px}}
.line{{color:#888;margin:0 4px}}
.summary{{margin-bottom:10px}}.s{{margin-right:14px;font-weight:bold}}
</style></head><body>
<h1>{html.escape(app)} · 全缺陷跟踪路径报告</h1>
<div class=meta>任务ID {html.escape(taskid)} ｜ 分支 {html.escape(branch or "-")} ｜ 提交 {html.escape((commit or "")[:12])} ｜ {html.escape(scanmode)} ｜ 导出时间 {out['meta']['exportedAt']}<br>
平台 {html.escape(base_url)} ｜ 缺陷总数 {len(defects)}</div>
<div class=summary>{summary}</div>
<table><tr><th style="width:15%">缺陷名称</th><th style="width:22%">风险点</th><th style="width:6%">等级</th><th>污点跟踪路径（全部）</th></tr>
{''.join(rows)}
</table></body></html>'''
open(out_html,'w').write(doc)
print(f"OK {len(defects)}")
PYEOF
if [ "$?" = "0" ]; then
DEFECTS_EXPORT_OK=1
log "全缺陷导出完成: ${DEFECTS_JSON_FILE} + ${DEFECTS_HTML_FILE}"
else
warn "缺陷导出渲染失败(JSON已尽力落盘)"; DEFECTS_JSON_FILE=""
fi
else
warn "执行机无 python3，跳过缺陷导出(仅PDF报告)"
DEFECTS_JSON_FILE=""
fi
rm -rf "$_tr_dir" "$_d_all"
fi
GATE_RESULT="未启用(仅告警)"
if [ "$GATE_ENABLED" = "1" ]; then
if [ "${SUPER_COUNT:-0}" -gt "$GATE_SUPER" ] || [ "${HIGH_COUNT:-0}" -gt "$GATE_HIGH" ] \
|| [ "${MIDDLE_COUNT:-0}" -gt "$GATE_MIDDLE" ] || [ "${LOW_COUNT:-0}" -gt "$GATE_LOW" ]; then
GATE_RESULT="⛔ 不通过"
else
GATE_RESULT="✅ 通过"
fi
fi
RAW_RESULT_JSON=$(jq -n \
--arg app "$APP_NAME" --arg taskid "$taskId" --arg appid "$poll_app" \
--arg title "$SCAN_TITLE" --arg gate "$GATE_RESULT" --arg url "$SAST_URL" \
--arg detailurl "${SAST_URL}/detection/code/${poll_app}/${taskId}/details/result" \
--arg increment "${increment}" \
--arg branch "$GIT_BRANCH" --arg author "$GIT_AUTHOR" --arg commit "$GIT_COMMIT" \
--arg build "$BUILD_URL" --arg time "$(date '+%Y-%m-%d %H:%M:%S')" \
--arg scanmode "$SCAN_TYPE_DESC" \
--arg reporturl "${SAST_URL}/detection/code" \
--arg project "${SAST_PROJECT_NAME:-快速检测}" \
--arg reportkind "${SAST_REPORT_KIND}" \
--arg reportfile "${report_pdf:-}" \
--arg defectsfile "${DEFECTS_JSON_FILE:-}" \
--arg defectshtml "${DEFECTS_HTML_FILE:-}" \
--argjson sup "${SUPER_COUNT:-0}" --argjson high "${HIGH_COUNT:-0}" \
--argjson mid "${MIDDLE_COUNT:-0}" --argjson low "${LOW_COUNT:-0}" \
--arg sku "${SKU_ID:-}" --arg biz "${BIZ_LINE:-}" \
'{scanTitle:$title, appName:$app, branch:$branch, author:$author, commit:$commit,
platformUrl:$url, appId:$appid, taskId:$taskid, scanTime:$time, scanMode:$scanmode,
reportUrl:$reporturl, detailUrl:$detailurl, incremental:($increment=="1"),
sku:(if $sku!="" then $sku else null end), biz:(if $biz!="" then $biz else null end),
projectName:$project,
reportKind:$reportkind, reportFile:$reportfile,
defectsFile:$defectsfile, defectsHtml:$defectshtml,
defectCount:{super:$sup, high:$high, middle:$mid, low:$low},
gateResult:$gate, buildUrl:$build}')
[ -n "$RESULT_JSON_FILE" ] && echo "$RAW_RESULT_JSON" > "$RESULT_JSON_FILE" 2>/dev/null || true
MSG_BODY=$(build_msg_body "$GATE_RESULT")
notify_send "${SCAN_TITLE}·${APP_NAME}" "$MSG_BODY"
echo "======================================================"
echo "  灵脉CodeAI 扫描结果   appId=${poll_app}  taskId=${taskId}"
echo "  扫描方式: ${SCAN_TYPE_DESC}"
echo "  超危: ${SUPER_COUNT}   高危: ${HIGH_COUNT}   中危: ${MIDDLE_COUNT}   低危: ${LOW_COUNT}"
echo "  质量门禁: ${GATE_RESULT}"
echo "  报告类型: ${SAST_REPORT_KIND}(DEFECT=详情)"
[ -n "${DEFECTS_JSON_FILE:-}" ] && echo "  全缺陷+跟踪路径: ${DEFECTS_JSON_FILE} + ${DEFECTS_HTML_FILE}"
echo "  平台地址: ${SAST_URL}"
echo "======================================================"
rm -f "$PKG_FILE"
if [ "$GATE_ENABLED" = "1" ] && [ "$GATE_RESULT" = "⛔ 不通过" ]; then
echo "$LOG_PREFIX 质量门禁不通过: 超危>${GATE_SUPER} 高危>${GATE_HIGH} 中危>${GATE_MIDDLE} 低危>${GATE_LOW}"
exit 1
fi
exit 0
