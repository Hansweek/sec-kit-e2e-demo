#!/usr/bin/env bash
# ============================================================================
#  灵脉CodeAI 增量感知扫描脚本 (codeai-incremental-scan.sh) · CI 平台无关单文件版
# ----------------------------------------------------------------------------
#  用途: 提交即扫(push=增量) / 发版(tag=全量) / 定时巡检(强制全量)，一条命令接入
#        GitHub Actions、GitLab-CI、阿里云效 Flow、Jenkins 等任意 CI。
#  逻辑来源: 元鼎智能交付 codeai-gitlab-ci-kit 五阶段流水线（2026-09-21 演示环境
#            全链路实测通过）。本脚本仅做"平台无关化"重构：GitLab stage → 函数，
#            接口报文与平台行为逻辑保持原样；仅增加三处安全网：
#            ① 终止态(4=检测失败/5=已停止/9=已阻断)按 BY_PASS 策略分流：放行模式
#               不挡发布只告警，严格模式才置红；
#            ② 应用名中的 / 与空格转义，避免打包文件名非法；
#            ③ 排队超时放行(BY_PASS)时补发一条钉钉/群通知，便于事后回看平台结果；
#            ④ TLS 校验默认 -k 跳过(内网平台普遍自签证书)；客户环境已配受信证书时
#               置 TLS_INSECURE=0 启用严格校验；
#            ⑤ 双保险超时：BY_PASS 超时(默认60分钟)外另有硬上限 HARD_TIMEOUT_MINUTES
#               (默认180分钟)，BY_PASS=0 严格模式也不会死等；
#            ⑥ 平台连续多轮返回异常(令牌失效/网络断/5xx)时快速失败，不空转到超时。
#  报文规则(2026-09-21 平台实测，勿改):
#    增量: addTaskJson 带 incrementSwitch:"1" + diff 文件 + gitHash → 平台生成新应用
#          记录并记录基线hash
#    全量+已有应用: 不带 incrementSwitch 字段 → 任务归并到该应用; gitHash 照带,
#          任务完成时回写hash
#    全量+首次(无同名应用): 带 incrementSwitch:"0" + gitHash → 平台新建应用并记录基线
#    101104 = 该应用已有排队/检测中任务(并发保护), 此时直接等待其结果
#  接口(全部 Open API):
#    ① 按应用名查已有应用      GET  /sast/api-v1/open-api/app/task/info
#    ② 新建应用id(首次)        GET  /sast/api-v1/open-api/app/generate/id
#    ③ 查平台侧扫描基线hash    GET  /sast/api-v1/open-api/app/git/hash/{appId}
#    ④ 提交检测任务            POST /sast/api-v1/open-api/app/saveOrAgainTask
#    ⑤ 轮询任务结果            GET  /sast/api-v1/open-api/defect/jenkins/result
#    ⑥ 生成/下载PDF报告(详情)  POST /sast/api-v1/open-api/defect/common/generate/report
#       reportComponent=DEFECT(详情报告,含每缺陷条目) / ANALYSE(概要)
#       旧 blue/* 端点保留为兜底
#  v2 增强(2026-10-12, 基于 CodeAI 5.0 实测):
#    ⑦ 全缺陷导出(数量不限)    GET  /sast/api-v1/open-api/defect/issue?taskId=...
#    ⑧ 每缺陷全跟踪路径        GET  /sast/api-v1/open-api/defect/risk/file/trace?riskFileIssueId=...
#       → sec-results/sast-defects-full.json + sast-defects-full.html(人工可读)
#    ⑨ 项目自动纳管v2: 按令牌归属人(SAST_USERNAME→userId+部门)建项目,
#       项目经理=令牌归属人, 归属部门=令牌归属人部门, 仓库协作人(SAST_PROJECT_MEMBERS)
#       自动解析为平台用户并加入项目成员(创建时生效)
#    ⑩ 用户/部门解析           GET  /sast/api-v1/open-api/system/user/page?username=
#  用法(手动冒烟):
#    SAST_URL=https://codeai.customer.local SAST_TOKEN=xxxx \
#    APP_NAME=demo-main bash codeai-incremental-scan.sh
#  退出码: 0=扫描完成且门禁通过(或未启用)  1=门禁不通过  2=脚本/环境/平台错误
# ============================================================================
set -uo pipefail
# 抵消CI外层(云效等)可能继承的 errexit: 本脚本全程显式错误处理, 不依赖 -e
set +e

# ----------------------------------------------------------------------------
# 【一】必填配置
# ----------------------------------------------------------------------------
: "${SAST_URL:?请设置环境变量 SAST_URL (CodeAI平台地址，如 https://192.168.x.x，结尾不带/)}"
: "${SAST_TOKEN:?请设置环境变量 SAST_TOKEN (平台右上角头像→个人中心→访问令牌)}"

# ----------------------------------------------------------------------------
# 【二】可选配置（默认值即推荐值，按客户情况覆盖）
# ----------------------------------------------------------------------------
APP_NAME="${APP_NAME:-}"                  # 应用名；留空则自动取 仓库名-分支名。同名自动复用应用并延续增量基线
SAST_PROJECT_ID="${SAST_PROJECT_ID:-0}"   # 项目管理ID；0=不归入项目管理(快速检测)。配置后任务/应用挂到该项目下
SAST_PROJECT_NAME="${SAST_PROJECT_NAME:-}"  # 项目名称(与平台项目管理中的名称一致)；未配ID时按名称自动解析，平台无同名项目时自动创建
SAST_PROJECT_AUTO_CREATE="${SAST_PROJECT_AUTO_CREATE:-1}"  # 1=平台无同名项目时自动创建(实测接口); 0=只查找不创建
SAST_PROJECT_PM_ID="${SAST_PROJECT_PM_ID:-}"    # 项目经理用户ID。v2: 留空时自动取令牌归属人(需配 SAST_USERNAME)，再回退平台默认管理员=1
SAST_PROJECT_DEPT_ID="${SAST_PROJECT_DEPT_ID:-}"  # 归属部门ID。v2: 留空时自动取令牌归属人部门，再回退默认部门=1
SAST_USERNAME="${SAST_USERNAME:-}"        # 令牌归属人的平台用户名(个人中心可见)。用于自动解析 项目经理/归属部门(OpenAPI无whoami)
SAST_PROJECT_MEMBERS="${SAST_PROJECT_MEMBERS:-}"  # 仓库协作人平台用户名列表(逗号分隔,CI侧由 GitHub collaborators 映射注入)。
                                             # 自动建项目时解析为平台用户加入成员; 与部门成员(departmentIds)互补
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
# ---- v2: 报告与导出 ----
SAST_REPORT_KIND="${SAST_REPORT_KIND:-ANALYSE}"  # ANALYSE=概要报告(默认,图表化重点视图) DEFECT=详情报告 BOTH=概要+重点详情双报告
BASELINE_CACHE_DIR="${BASELINE_CACHE_DIR:-$SCAN_DIR/.sast-baseline}"  # CI侧增量基线缓存(平台基线缺失时兜底, CI缓存跨次保留)
# 报告包含的审计状态(平台审计状态枚举 0未审计 1已审计-误报 2已审计-忽略 3超危 4高危 5中危 6低危 7已修复)
# 默认排除 1(误报) 2(忽略)：已判定为非问题的条目不再进入报告与缺陷清单
SAST_REPORT_AUDIT_STATUS="${SAST_REPORT_AUDIT_STATUS:-0,3,4,5,6}"
EXPORT_DIR="${EXPORT_DIR:-$SCAN_DIR/sec-results}"  # 全缺陷+跟踪路径导出目录(与SCA产物同目录,便于统一归档)
EXPORT_DEFECTS="${EXPORT_DEFECTS:-1}"       # 1=导出全缺陷+全跟踪路径(JSON+HTML) 0=关闭(大仓库赶时间时)
DEFECTS_PAGE_SIZE="${DEFECTS_PAGE_SIZE:-200}"     # defect/issue 分页大小(平台接受200,数量不限=自动翻页)
TRACE_CONCURRENCY="${TRACE_CONCURRENCY:-6}"       # 跟踪路径并发拉取数

# 质量门禁(灰度期建议全 0 只告警，稳定后 GATE_ENABLED=1 启用阻断)
GATE_ENABLED="${GATE_ENABLED:-0}"
GATE_SUPER="${GATE_SUPER:-0}"
GATE_HIGH="${GATE_HIGH:-0}"
GATE_MIDDLE="${GATE_MIDDLE:-0}"
GATE_LOW="${GATE_LOW:-0}"

# 结果推送: 钉钉/企微/飞书群机器人
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
NOTIFY_TYPE="${NOTIFY_TYPE:-dingtalk}"    # dingtalk | wecom | feishu | raw
NOTIFY_SECRET="${NOTIFY_SECRET:-}"        # 钉钉"加签"密钥/飞书签名密钥(未启用则留空)
NOTIFY_AT="${NOTIFY_AT:-}"                # 钉钉@手机号，逗号分隔

# CI 注入的仓库信息(缺省自动从 git 读取)
GIT_BRANCH="${GIT_BRANCH:-}"
GIT_COMMIT="${GIT_COMMIT:-}"
GIT_AUTHOR="${GIT_AUTHOR:-}"
BUILD_URL="${BUILD_URL:-}"

# ----------------------------------------------------------------------------
# 【公共区】工具函数（与 codeai-scan.sh 同一套实现，勿改动）
# ----------------------------------------------------------------------------
SCAN_TITLE="灵脉CodeAI代码安全扫描"
LOG_PREFIX="[CodeAI]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }
die()  { echo "$LOG_PREFIX [错误] $*" >&2; exit 2; }

for cmd in curl jq zip git; do
  command -v "$cmd" >/dev/null 2>&1 || die "缺少命令 [$cmd]，请先安装: yum install -y curl jq zip 或 apt-get install -y curl jq zip"
done

# 网络重试封装: 关键接口遇 超时/5xx/连接失败 自动重试(平台/链路抖动很常见, 不重试会把抖动变成流水线红)
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
# 令牌/权限错误统一翻译: 直接告诉用户去哪处理, 不留模糊报错
sast_check_auth() {  # sast_check_auth <响应>
  local code
  code=$(printf '%s' "$1" | jq -r '.code // 0' 2>/dev/null)
  case "$code" in
    401) die "平台返回401: SAST_TOKEN 无效或已过期。请到 ${SAST_URL} 右上角头像→个人中心→访问令牌 重新生成, 并更新 CI Secrets/变量中的令牌" ;;
    403) die "平台返回403: 当前令牌权限不足(需要项目管理/检测权限)。请联系平台管理员核对令牌归属账号的角色" ;;
  esac
}
# TLS 证书校验开关: 1=跳过(默认，内网自签证书) 0=严格校验(平台已配受信证书时)
TLS_INSECURE="${TLS_INSECURE:-1}"
[ "$TLS_INSECURE" = "1" ] && TLS_FLAGS="-k" || TLS_FLAGS=""
sast_jq()   { echo "$1" | jq -r "$2" 2>/dev/null; }
urlencode() { printf '%s' "$1" | jq -sRr '@uri'; }

# ---- 业务标识解析: SKU/业务线(命名体系 v3, 对应9/24会议 SKU分支分层决议) ----
# 优先级: 显式变量(SKU_ID/BIZ_LINE) > 分支名模式(sku/<SKU> | sku-<SKU>) > 空
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

# 出网URL校验: 仅允许 http/https; 拒绝 localhost/环回/链路本地/元数据/保留地址。
# 说明: 私网地址(RFC1918)为本产品受支持的内网部署形态, 放行并打日志提示。
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
### ${SCAN_TITLE}
**应用**: ${APP_NAME}
**分支/提交**: ${GIT_BRANCH:-N/A} / ${GIT_COMMIT:-N/A} ${GIT_AUTHOR:+by ${GIT_AUTHOR}}
**扫描方式**: ${SCAN_TYPE_DESC:-全量扫描}
**缺陷统计**: 超危 **${SUPER_COUNT:-0}** | 高危 **${HIGH_COUNT:-0}** | 中危 **${MIDDLE_COUNT:-0}** | 低危 **${LOW_COUNT:-0}**
**质量门禁**: ${gate_line}
**报告下载**: [平台查看/下载检测报告](${SAST_URL}/detection/code)（登录后按应用名 ${APP_NAME} 查看；PDF 已同步归档 CI 产物 sast_report.pdf）
**项目归属**: ${SAST_PROJECT_NAME:-快速检测}
EOF
}

# ============================================================================
# 主流程
# ============================================================================
log "==== 灵脉CodeAI 增量感知扫描开始 ===="

# ---- ① 身份推导: 应用名 / 分支 / 完整commit ----
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

# ---- ② 打包源码（与平台侧 git diff 的相对路径保持一致） ----
# 排除模式注意: Info-ZIP 的 -x 对归档内路径做整串 glob 匹配，裸目录名(如 -x .git)
# 只匹配目录条目本身、不排除其内容(实测)。因此目录类排除需同时给 4 种派生模式，
# 兼容 *.log 这类自带通配的项(多余模式为无害 no-op)，并覆盖 monorepo 嵌套目录。
PKG_FILE="${SCAN_DIR}/${SAFE_NAME}.zip"
rm -f "$PKG_FILE"
# 磁盘预检: 工作区剩余空间不足1GB时提前警告(打包/上传都会因磁盘满产生难以理解的失败)
_avail_kb=$(df -k "$SCAN_DIR" 2>/dev/null | awk 'NR==2{print $4}')
[ -n "$_avail_kb" ] && [ "$_avail_kb" -lt 1048576 ] && warn "工作区剩余空间不足1GB(当前${_avail_kb}KB), 大仓库可能打包/落盘失败, 请清理后重试"
_x_args=()
for pat in $EXCLUDES; do _x_args+=(-x "$pat" -x "$pat/*" -x "*/$pat" -x "*/$pat/*"); done
( cd "$SCAN_DIR" && zip -rq "$PKG_FILE" . ${_x_args[@]+"${_x_args[@]}"} ) || die "源码打包失败"
log "源码已打包: ${PKG_FILE} ($(du -h "$PKG_FILE" | cut -f1))"

# ---- ③ 项目维度归属 v2 → 先于应用解析(应用按项目查找才可见) ----
# ---- ④½ 项目维度归属 v2: 令牌归属人→项目经理+部门, 仓库协作人→项目成员 ----
# 接口实测(2026-10-12 CodeAI 5.0 / sast.igovee.com):
#   GET  open-api/system/user/page?username=<u> → {userId, departmentId, departmentName}
#   POST open-api/project/add {projectName, pmId, departmentId, userIds[]}
#   ⚠ CodeAI 5.0 起 add 必须带 pmId+departmentId(旧版"仅项目名"报400)；
#     项目成员仅创建时生效(OpenAPI 无成员更新接口)，后续加人在平台 UI 操作
sast_user_page() {  # sast_user_page <username> → 输出 JSON行: userId|departmentId|nickname (空=未找到)
  local u="$1" resp
  [ -n "$u" ] || { echo ""; return; }
  resp=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/system/user/page?username=$(urlencode "$u")&pageNum=1&pageSize=10" --header "Sast-Token: ${SAST_TOKEN}")
  echo "$resp" | jq -r --arg u "$u" \
    '[.data.records[]? // empty | select(.username==$u)] | if length>0 then (.[0] | "\(.userId)|\(.departmentId // 1)|\(.nickname // .username)") else "" end' 2>/dev/null
}

if [ "${SAST_PROJECT_ID:-0}" = "0" ] && [ -n "${SAST_PROJECT_NAME:-}" ]; then
  log "按名称解析项目维度归属: ${SAST_PROJECT_NAME}"
  # -- 令牌归属人解析(项目经理+部门自动推导) --
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

  # -- 仓库协作人 → 平台用户ID(CI侧把 GitHub collaborators 注入 SAST_PROJECT_MEMBERS) --
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
        # 翻完无同名项目 → 自动创建(可用 SAST_PROJECT_AUTO_CREATE=0 关闭)
        if [ "${SAST_PROJECT_AUTO_CREATE}" != "1" ]; then
          die "平台项目管理中不存在名为[${SAST_PROJECT_NAME}]的项目, 且已关闭自动创建: 请先在平台创建, 或配 SAST_PROJECT_ID(数字)"
        fi
        # 实测边界(2026-10-10): 创建返回1500014=名称已存在但分页查询不可见
        # (常见于流水线令牌与建项目账号不同, 项目按账号可见而名称全局唯一) → 重新解析一轮, 仍不可见则给处置指引
        if [ "${_pm_retried}" = "1" ]; then
          die "项目[${SAST_PROJECT_NAME}]已存在但当前令牌不可见。处理: ①确认令牌归属账号与该项目一致(或配 SAST_USERNAME); ②平台把该项目授权给流水线账号; ③删除该项目后重跑流水线自动重建; ④直接配 SAST_PROJECT_ID=<项目数字ID>"
        fi
        log "平台无同名项目 → 自动创建项目 ${SAST_PROJECT_NAME} (PM=userId:${SAST_PROJECT_PM_ID}, 部门=${SAST_PROJECT_DEPT_ID}${_member_ids:+, 成员=[${_member_ids}]}) ..."
        # 两段式创建: 先带负责人/部门/成员; 被拒时降级仅项目名(旧版4.x兼容)
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

# ---- ③½ 按应用名解析 appId（复用已有应用 → 版本对比/增量基线可延续） ----
# CodeAI 5.0 实测(2026-10-12): 归入项目的应用必须按项目维度查
#   GET open-api/app/info/{projectId}?appName=<精确>&pageNum=1&pageSize=50
# 快速检测(无项目)或旧版本回退: GET open-api/app/task/info?name=&isLike=true
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

# ---- ④ 计算增量范围：上次扫描 hash ↔ 本次提交 的变更文件清单 ----
# 基线来源两级: ①平台 open-api/app/git/hash/{appId}(全量任务后会回写)
#              ②CI侧缓存文件(兜底: 5.0实测增量任务完成后平台不回写gitHash,
#                若只依赖平台基线会出现"增量→全量→增量"交替, 见2026-10-28排查)
increment=0
SCAN_TYPE_DESC="全量扫描"
DIFF_FILE="${SCAN_DIR}/${SAFE_NAME}.txt"
BASELINE_SRC="平台"
if [ "$FORCE_FULL" = "1" ]; then
  log "强制全量(FORCE_FULL=1，定时巡检/手动指定)"
elif [ -n "$CI_COMMIT_TAG" ]; then
  log "发版(tag=${CI_COMMIT_TAG})触发 → 全量扫描"
else
  hash=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/app/git/hash/${app_id}" --header "Sast-Token: ${SAST_TOKEN}" | jq -r '.data')
  if [ "$hash" = "null" ] || [ -z "$hash" ]; then
    _cached=""
    [ -r "${BASELINE_CACHE_DIR}/${SAFE_NAME}" ] && _cached=$(tr -d ' \r\n' < "${BASELINE_CACHE_DIR}/${SAFE_NAME}" 2>/dev/null)
    if [ -n "$_cached" ] && git -C "$SCAN_DIR" cat-file -e "${_cached}^{commit}" 2>/dev/null; then
      hash="$_cached"; BASELINE_SRC="CI缓存"
      log "平台基线缺失(增量任务后平台不回写), 回退CI缓存基线: ${hash}"
    fi
  fi
  echo "上次扫描 hash(${BASELINE_SRC}): ${hash}"
  if [ "$hash" != "null" ] && [ -n "$hash" ]; then
    git -C "$SCAN_DIR" diff --name-only "${hash}" "${last_commit}" > "$DIFF_FILE" || true
    if [ -s "$DIFF_FILE" ]; then
      log "存在变更文件 → 增量扫描"; cat "$DIFF_FILE"
      increment=1
      SCAN_TYPE_DESC="增量扫描(基线[${BASELINE_SRC}] ${hash:0:8} → ${last_commit:0:8})"
    else
      log "无文件变更 → 按全量提交"
    fi
  else
    log "无扫描基线(首次) → 全量扫描"
  fi
fi
[ -f "$DIFF_FILE" ] || echo "" > "$DIFF_FILE"

# ---- ⑤ 提交检测任务 ----
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
# incrementSwitch 必须显式携带: 平台将其作为应用级持久属性, 缺省时沿用应用上一次的模式
# (实测: 应用上次为增量而本次缺省不传 → 平台按增量受理但无diff文件 → 8秒即status=4检测失败)
if [ "${increment}" = "1" ]; then
  add_task_json=$(echo "$add_task_json" | jq -c '. + {incrementSwitch:"1"}')
else
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
  # 平台行为实测(2026-10-09 Govee现场): 新建应用时 data=新appId;
  # 归并到已有应用(复用+全量)时 data=null —— 此时轮询对象应回退为
  # prepare_app 阶段解析出的 app_id, 不能把字符串"null"当 appId 去轮询
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

# ---- ⑥ 等待结果 → 汇总缺陷 → 生成并下载报告 → 门禁 → 通知 ----
# 状态机口径: 3=完成(唯一成功出口); 1排队/2检测中/0待处理(文档口径,元鼎实测亦等待)/
# 8=生成结果中 → 持续等待; 4=检测失败/5=已停止/9=已阻断 → 按 BY_PASS 分流;
# 其余(null/空/非0非5003的code) → 连续异常计数, 超阈值快速失败防死等
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
      # 终止态: 灰度原则 BY_PASS=1 放行不挡发布(通知里可见), 严格模式才置红
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

# 任务完成 → 回写CI侧基线缓存(增量任务平台不回写gitHash, 下次据此延续增量)
if [ "${taskId}" != "0" ] && [ -n "${taskId}" ]; then
  mkdir -p "$BASELINE_CACHE_DIR" 2>/dev/null && echo "$last_commit" > "${BASELINE_CACHE_DIR}/${SAFE_NAME}" 2>/dev/null || true
fi

# 汇总各级缺陷数（openJenkinsFlawInfoMap按BUG/VULNERABILITY/CODE_SMELL分类，逐项相加）
result_resp="$response"
SUPER_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].superCount] | add // 0')
HIGH_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].highCount] | add // 0')
MIDDLE_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].middleCount] | add // 0')
LOW_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].lowCount] | add // 0')
log "缺陷统计: 超危=${SUPER_COUNT} 高危=${HIGH_COUNT} 中危=${MIDDLE_COUNT} 低危=${LOW_COUNT}"

log "生成检测报告(类型=${SAST_REPORT_KIND}: ANALYSE=概要 DEFECT=详情 BOTH=双报告; 审计状态=${SAST_REPORT_AUDIT_STATUS})..."
enc_name=$(urlencode "${APP_NAME}")
report_pdf=""
report_pdf_detail=""
AUDIT_STATUS_JSON=$(printf '%s' "${SAST_REPORT_AUDIT_STATUS}" | tr -d ' ' \
  | jq -R 'split(",") | map(select(test("^[0-9]+$")) | tonumber)' 2>/dev/null)
[ -n "$AUDIT_STATUS_JSON" ] && [ "$AUDIT_STATUS_JSON" != "[]" ] || AUDIT_STATUS_JSON='[0,3,4,5,6]'
gen_report_via_common() {  # $1=reportComponent $2=报告名后缀 → 输出 reportId 或空
  local rc="$1" resp rid
  resp=$(sast_curl --request POST --url "${SAST_URL}/sast/api-v1/open-api/defect/common/generate/report" \
    -H "Sast-Token: ${SAST_TOKEN}" -H "Content-Type: application/json" \
    -d "$(jq -n --arg rc "$rc" --arg rn "${APP_NAME}${2}" \
        --arg app "${poll_app}" --arg tid "${taskId}" --argjson ast "${AUDIT_STATUS_JSON}" \
        '{reportType:1, reportName:$rn, appId:$app, taskId:$tid, reportComponent:$rc, auditStatusType:$ast}')")
  rid=$(sast_jq "$resp" '.data')
  { [ -n "$rid" ] && [ "$rid" != "null" ]; } || { warn "common端点未受理(${rc}): $(echo "$resp" | head -c 150)"; echo ""; return; }
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
wait_and_download() {  # $1=reportId $2=目标文件
  local rid="$1" out="$2" r_status="" r_start=$(date +%s)
  while [ "$r_status" != "2" ]; do
    sleep 5
    r_status=$(sast_curl --request GET \
        --url "${SAST_URL}/sast/api-v1/open-api/defect/common/generate/report/status?reportId=${rid}" \
        -H "Sast-Token: ${SAST_TOKEN}" | jq -r '.data.status // 0' 2>/dev/null)
    if [ $(( $(date +%s) - r_start )) -gt 600 ]; then warn "报告生成超时(10分钟，详情报告较大属正常，可稍后在平台下载)，跳过"; return; fi
  done
  if [ "$r_status" = "3" ]; then warn "平台报告生成失败(status=3): ${out}"; return; fi
  sast_curl --request GET \
      --url "${SAST_URL}/sast/api-v1/open-api/defect/common/download/report?reportId=${rid}" \
      -H "Sast-Token: ${SAST_TOKEN}" -o "$out"
  if head -c 4 "$out" 2>/dev/null | grep -q "%PDF"; then
    log "PDF报告已下载: ${out} ($(du -h "$out" | cut -f1))"
  else
    warn "common下载失败，尝试blue端点..."
    sast_curl --request GET \
      --url "${SAST_URL}/sast/api-v1/open-api/defect/blue/download/report?reportId=${rid}" \
      -H "Sast-Token: ${SAST_TOKEN}" -o "$out"
    head -c 4 "$out" 2>/dev/null | grep -q "%PDF" && log "PDF报告已下载: ${out}" || warn "报告下载失败(保留平台侧报告记录)"
  fi
}
case "${SAST_REPORT_KIND}" in
  DEFECT)  # 仅详情报告(带审计状态过滤)
    REPORT_ID=$(gen_report_via_common DEFECT "")
    [ -z "$REPORT_ID" ] && REPORT_ID=$(gen_report_via_blue)
    if [ -n "$REPORT_ID" ]; then
      report_pdf_detail="${REPORT_DIR}/sast-report-defects.pdf"
      wait_and_download "$REPORT_ID" "$report_pdf_detail"
    else
      warn "报告创建失败，跳过报告下载(可在平台 检测报告 页面手动生成)"
    fi
    ;;
  BOTH)    # 概要(管理层视图) + 重点详情(审计过滤后) 双报告; 先发详情生成请求(耗时)再取概要
    RID_D=$(gen_report_via_common DEFECT "(重点)")
    RID_A=$(gen_report_via_common ANALYSE "(概要)")
    [ -n "$RID_A" ] && { report_pdf="${REPORT_DIR}/sast-report.pdf"; wait_and_download "$RID_A" "$report_pdf"; }
    [ -n "$RID_D" ] && { report_pdf_detail="${REPORT_DIR}/sast-report-defects.pdf"; wait_and_download "$RID_D" "$report_pdf_detail"; }
    ;;
  *)       # ANALYSE(默认): 图表化概要, 研发/管理层一眼看到重点
    REPORT_ID=$(gen_report_via_common ANALYSE "")
    [ -z "$REPORT_ID" ] && REPORT_ID=$(gen_report_via_blue)
    if [ -n "$REPORT_ID" ]; then
      report_pdf="${REPORT_DIR}/sast-report.pdf"
      wait_and_download "$REPORT_ID" "$report_pdf"
    else
      warn "报告创建失败，跳过报告下载(可在平台 检测报告 页面手动生成)"
    fi
    ;;
esac

# ---- ⑥½ 全缺陷+全跟踪路径导出(数量不限; PDF详情报告的补充数据面) ----
DEFECTS_JSON_FILE=""; DEFECTS_HTML_FILE=""
if [ "${EXPORT_DEFECTS}" = "1" ] && [ "${taskId}" != "0" ] && [ -n "${taskId}" ]; then
  log "导出全缺陷清单+跟踪路径(供审计追溯, 与PDF报告同归档)..."
  mkdir -p "$EXPORT_DIR"
  DEFECTS_JSON_FILE="${EXPORT_DIR}/sast-defects-full.json"
  DEFECTS_HTML_FILE="${EXPORT_DIR}/sast-defects-full.html"
  _d_page=1; _d_all="/tmp/sast-defects-$$.jsonl"; : > "$_d_all"; _d_total=0; _d_skip=0
  while :; do
    # 不传 isProblem: 该参数=0 时平台只返回未审计项, 会把已审计分级项(3~6)一并滤掉
    _d_resp=$(sast_curl --url "${SAST_URL}/sast/api-v1/open-api/defect/issue?taskId=${taskId}&pageNum=${_d_page}&pageSize=${DEFECTS_PAGE_SIZE}" --header "Sast-Token: ${SAST_TOKEN}")
    if [ "$(sast_jq "$_d_resp" '.code')" != "0" ]; then
      warn "缺陷清单第${_d_page}页拉取失败: $(echo "$_d_resp" | head -c 120)"; break
    fi
    _d_cnt=$(echo "$_d_resp" | jq -r '.data.records | length' 2>/dev/null)
    # 与报告口径一致: 剔除 auditStatus=1(已审计-误报)/2(已审计-忽略)
    echo "$_d_resp" | jq -c --argjson ast "${AUDIT_STATUS_JSON}" '.data.records[]? | .auditStatus as $s | select(($ast | index($s)) != null)' >> "$_d_all" 2>/dev/null
    _d_keep=$(echo "$_d_resp" | jq --argjson ast "${AUDIT_STATUS_JSON}" '[.data.records[]? | .auditStatus as $s | select(($ast | index($s)) != null)] | length' 2>/dev/null)
    _d_total=$((_d_total + ${_d_keep:-0}))
    _d_skip=$((_d_skip + ${_d_cnt:-0} - ${_d_keep:-0}))
    _d_sum=$(sast_jq "$_d_resp" '.data.total'); _d_sum=${_d_sum:-0}; [ "$_d_sum" = "null" ] && _d_sum=0
    [ "$_d_cnt" -lt "${DEFECTS_PAGE_SIZE}" ] && break
    [ $(( _d_total + _d_skip )) -ge "$_d_sum" ] && break
    _d_page=$((_d_page + 1))
  done
  log "缺陷清单共 ${_d_total} 条（已剔除误报/忽略 ${_d_skip} 条），开始拉取跟踪路径(并发=${TRACE_CONCURRENCY})..."
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
  # 合成结构化JSON + HTML(python3渲染; 无python3时仅JSON)
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
# HTML(黑白灰打印风格, 按风险等级分组, 展示全部路径)
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
  --arg reportaudit "${SAST_REPORT_AUDIT_STATUS}" \
  --arg reportfile "${report_pdf:-}" \
  --arg reportdetail "${report_pdf_detail:-}" \
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
    reportKind:$reportkind, reportAuditStatus:$reportaudit,
    reportFiles:[$reportfile, $reportdetail] | map(select(length>0)),
    reportFile:$reportfile,
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
echo "  报告类型: ${SAST_REPORT_KIND} (ANALYSE=概要 DEFECT=详情 BOTH=双报告)"
echo "  报告审计状态: ${SAST_REPORT_AUDIT_STATUS} (1=已审计-误报 2=已审计-忽略 已排除)"
[ -n "${DEFECTS_JSON_FILE:-}" ] && echo "  全缺陷+跟踪路径: ${DEFECTS_JSON_FILE} + ${DEFECTS_HTML_FILE}"
echo "  平台地址: ${SAST_URL}"
echo "======================================================"

rm -f "$PKG_FILE"

if [ "$GATE_ENABLED" = "1" ] && [ "$GATE_RESULT" = "⛔ 不通过" ]; then
  echo "$LOG_PREFIX 质量门禁不通过: 超危>${GATE_SUPER} 高危>${GATE_HIGH} 中危>${GATE_MIDDLE} 低危>${GATE_LOW}"
  exit 1
fi
exit 0
