#!/usr/bin/env bash
# ============================================================================
#  灵脉CodeAI 通用代码安全扫描脚本 (codeai-scan.sh)
# ----------------------------------------------------------------------------
#  用途 : 把源码打包上传到灵脉CodeAI平台检测，等结果、下报告、(可选)质量门禁、
#         (可选)推送扫码结果到钉钉/企业微信/飞书群。
#  通用 : GitLab CI、Jenkins Pipeline、手动执行均可用同一份脚本，
#         所有配置全部通过"环境变量"传入，换客户/换项目只改变量，不改代码。
#  依赖 : curl、jq、zip 三个命令（执行机器上必须安装）。
#         未安装时执行下面命令（二选一）:
#           CentOS/RHEL:  sudo yum install -y curl jq zip
#           Ubuntu/Debian: sudo apt-get install -y curl jq zip
#  原理 : 全部通过平台 Open API 完成（与官方"下载脚本"同一套接口）:
#         ① 按应用名查已有应用(复用appId)  GET  /sast/api-v1/open-api/app/task/info
#         ② 新建应用id(首次)              GET  /sast/api-v1/open-api/app/generate/id
#         ③ 提交检测任务                   POST /sast/api-v1/open-api/app/saveOrAgainTask
#         ④ 轮询任务结果                   GET  /sast/api-v1/open-api/defect/jenkins/result
#         ⑤ 生成/下载PDF报告              GET  /sast/api-v1/open-api/defect/blue/*
#  退出码: 0=扫描完成且门禁通过(或未启用门禁)  1=门禁不通过  2=脚本自身出错
# ============================================================================

# ----------------------------------------------------------------------------
# 【一】必填配置（没有默认值，不填脚本会直接报错退出并提示）
# ----------------------------------------------------------------------------
# SAST_URL    : CodeAI平台地址。注意带 https:// 或 http://，结尾不要带 /
# SAST_TOKEN  : 平台右上角头像 → 个人中心 → 访问令牌 → 复制
# APP_NAME    : 应用名称。同一个应用每次构建用同一个名字，平台里会归到一起，
#               并自动做"版本对比/增量检测"，推荐格式: 项目名-分支名
# 用法示例(手动测试):
#   SAST_URL=https://192.168.172.131 SAST_TOKEN=xxxx APP_NAME=myapp ./codeai-scan.sh

: "${SAST_URL:?请设置环境变量 SAST_URL (CodeAI平台地址，如 https://192.168.172.131)}"
: "${SAST_TOKEN:?请设置环境变量 SAST_TOKEN (个人中心-访问令牌)}"
: "${APP_NAME:?请设置环境变量 APP_NAME (应用名称，如 mall-service-develop)}"

# ----------------------------------------------------------------------------
# 【二】常用可选配置（都给了默认值，按需覆盖）
# ----------------------------------------------------------------------------
APP_REUSE="${APP_REUSE:-1}"              # 1=按APP_NAME复用平台已有应用(推荐，不产生垃圾应用) 0=每次新建应用
AUTO_LANGUAGE="${AUTO_LANGUAGE:-1}"      # 1=自动语言识别(推荐，无需配置语言和模板ID，通用性最强) 0=需手动指定
SCAN_MODE="${SCAN_MODE:-1}"               # 扫描方式: 1=快速扫描(分钟级) 2=深度扫描(更全更慢)
PROJECT_MODE="${PROJECT_MODE:-1}"        # 检测信息保存位置: 1=快速检测 2=项目管理(需再提供PROJECT_ID)
PROJECT_ID="${PROJECT_ID:-0}"             # PROJECT_MODE=2 时填项目管理里查到的项目ID
SCAN_DIR="${SCAN_DIR:-$PWD}"              # 要打包扫描的目录，默认当前目录(workspace/CI目录)
EXCLUDES="${EXCLUDES:-.git node_modules target build dist .idea .vscode *.log *.zip codeai-scan.sh sast_report.pdf}"  # 打包时排除的目录/文件
REPORT_DIR="${REPORT_DIR:-$SCAN_DIR}"    # PDF报告落盘目录(Jenkins里可指向工作区以便归档)
POLL_INTERVAL="${POLL_INTERVAL:-15}"     # 轮询结果的间隔秒数
TIMEOUT_MINUTES="${TIMEOUT_MINUTES:-60}" # 等待扫描结果的最大分钟数，超时按BY_PASS策略处理
                                         # 注意: 平台为共享资源时(其他项目也在扫)任务会排队,
                                         # 大项目全量扫描+排队可能超30分钟,建议60以上
WAIT_RESULT="${WAIT_RESULT:-1}"          # 1=提交后等待检测结果(默认,可拿报告/推送/门禁)
                                         # 0=提交即走(异步):流水线只花打包上传时间,检测结果
                                         #   和PDF报告去平台"代码审计"页面查看;此模式下
                                         #   不推送群消息、质量门禁不生效
SCA_ENABLED="${SCA_ENABLED:-1}"          # 1=提交任务后自动补发"组件检测"(开源组件/SCA风险)
                                         # 说明: Open API提交的任务平台不会自动发起组件检测,
                                         #   需调executeScaAgain补发; 0=不发起(仅静态检测)
RESULT_JSON_FILE="${RESULT_JSON_FILE:-}" # 结果JSON落盘路径(供gitee-report.sh消费,如 ./codeai-result.json)

# 质量门禁: GATE_ENABLED=1 时，缺陷数超过任一阈值 → 退出码1(流水线置红)
GATE_ENABLED="${GATE_ENABLED:-0}"        # 0=不启用(只告警不阻断) 1=启用
GATE_SUPER="${GATE_SUPER:-0}"             # 超危阈值(超过则不通过)
GATE_HIGH="${GATE_HIGH:-0}"              # 高危阈值
GATE_MIDDLE="${GATE_MIDDLE:-0}"          # 中危阈值
GATE_LOW="${GATE_LOW:-0}"                # 低危阈值

# 异常放行策略(Bypass): CI最重要的原则是"安全平台故障不能拖垮业务发布"
BY_PASS="${BY_PASS:-1}"                  # 1=平台异常/超时时放行(构建不失败) 0=严格模式(直接失败)

# ----------------------------------------------------------------------------
# 【三】扫码结果推送配置（可选；不配则只在控制台打印结果）
# ----------------------------------------------------------------------------
# NOTIFY_WEBHOOK : 群机器人Webhook地址。三类平台任选其一:
#     钉钉    : 群设置→机器人→添加→自定义→安全设置选"加签"→复制Webhook和加签密钥
#     企业微信 : 群设置→机器人→添加→复制Webhook
#     飞书    : 群设置→机器人→添加自定义机器人→复制Webhook(如启用签名也填NOTIFY_SECRET)
# NOTIFY_TYPE    : dingtalk | wecom | feishu | raw(通用POST JSON，对接自有平台)
# NOTIFY_SECRET  : 钉钉"加签"密钥 或 飞书"签名"密钥(没启用加签/签名就不用填)
# NOTIFY_AT      : 钉钉需要@的人的手机号，多个用逗号分隔(如 13800000001,13800000002)
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
NOTIFY_TYPE="${NOTIFY_TYPE:-dingtalk}"
NOTIFY_SECRET="${NOTIFY_SECRET:-}"
NOTIFY_AT="${NOTIFY_AT:-}"

# ----------------------------------------------------------------------------
# 【四】展示信息（由CI系统自动注入或手动填写，会出现在推送消息里，增强可读性）
# ----------------------------------------------------------------------------
SCAN_TITLE="${SCAN_TITLE:-代码安全扫描}"  # 推送消息标题，如 "GitLab提交扫码"/"Jenkins编译后扫包"
GIT_BRANCH="${GIT_BRANCH:-}"              # 分支名
GIT_AUTHOR="${GIT_AUTHOR:-}"               # 提交人
GIT_COMMIT="${GIT_COMMIT:-}"              # 提交号(短hash即可)
GIT_MESSAGE="${GIT_MESSAGE:-}"            # 提交说明
BUILD_URL="${BUILD_URL:-}"                # Jenkins构建链接(点进去看完整日志)
PLATFORM_USER="${PLATFORM_USER:-}"        # 平台任务归属人(可留空,默认令牌本人)

# ============================================================================
# 以下为脚本实现，通常不需要修改 ↓↓↓
# ============================================================================
set -o pipefail

# 平台Open API的"任务来源"标记: 3001=Jenkins 3004=GitLab-CI 3009=通用Shell
# 只影响平台上显示的任务来源标签，不影响检测本身
TASK_SOURCE_TYPE="${TASK_SOURCE_TYPE:-3009}"

LOG_PREFIX="[CodeAI]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }
die()  { echo "$LOG_PREFIX [错误] $*" >&2; exit 2; }

# ---- 0. 环境自检：三个依赖命令缺一不可 ----
for cmd in curl jq zip; do
  command -v "$cmd" >/dev/null 2>&1 || die "缺少命令 [$cmd]，请先安装: yum install -y $cmd jq zip 或 apt-get install -y $cmd jq zip"
done

# 简化的curl封装: -s静默 -k忽略自签证书 --max-time防止网络挂死
sast_curl() { curl -s -k --max-time 120 "$@"; }

# 用jq安全取值: sast_jq <json串> <jq表达式>
sast_jq() { echo "$1" | jq -r "$2" 2>/dev/null; }

# urlencode（报告名等参数里有中文时必须编码；用jq实现，跨平台不挑bash版本）
urlencode() { printf '%s' "$1" | jq -sRr '@uri'; }

# ---------------------------------------------------------------------------
# 通知模块: 统一入口 notify_send <标题> <markdown正文> <是否@人>
# 支持 钉钉/企业微信/飞书/通用raw。推送失败只打日志，绝不影响扫描主流程。
# ---------------------------------------------------------------------------
notify_send() {
  local title="$1" body="$2" at_flag="$3"
  [ -z "$NOTIFY_WEBHOOK" ] && { log "未配置 NOTIFY_WEBHOOK，跳过结果推送"; return 0; }
  log "正在推送扫码结果到 $NOTIFY_TYPE ..."
  case "$NOTIFY_TYPE" in
    dingtalk)
      # 钉钉需要加签时: sign = base64(hmac_sha256(timestamp+"\n"+secret)) 再urlencode
      local url="$NOTIFY_WEBHOOK"
      if [ -n "$NOTIFY_SECRET" ]; then
        local ts sign
        ts=$(date +%s000)
        sign=$(printf '%s\n%s' "$ts" "$NOTIFY_SECRET" \
               | openssl dgst -sha256 -hmac "$NOTIFY_SECRET" -binary | base64)
        url="${url}&timestamp=${ts}&sign=$(urlencode "$sign")"
      fi
      # 钉钉markdown消息体；@人时追加@文本使手机号被高亮
      local at_text="" payload
      [ -n "$NOTIFY_AT" ] && at_text=" @${NOTIFY_AT//,/ @}"
      payload=$(jq -n --arg t "$title" --arg b "${body}${at_text}" \
        --arg ats "$NOTIFY_AT" \
        '{msgtype:"markdown",markdown:{title:$t,text:$b},
          at:{atMobiles:($ats|split(",")|map(select(length>0))),isAtAll:false}}')
      local resp
      resp=$(curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$url")
      log "钉钉推送返回: $resp"
      ;;
    wecom)
      # 企业微信机器人markdown消息体
      local payload
      payload=$(jq -n --arg c "$body" '{msgtype:"markdown",markdown:{content:$c}}')
      local resp
      resp=$(curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$NOTIFY_WEBHOOK")
      log "企业微信推送返回: $resp"
      ;;
    feishu)
      # 飞书自定义机器人text消息体；启用签名时: sign = base64(hmac_sha256(timestamp+"\n"+secret))
      # 注意: 飞书text消息不渲染markdown, 先去掉"###"和"**"标记避免原样显示星号
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
      log "飞书推送返回: $resp"
      ;;
    raw)
      # 通用webhook: 把结果JSON原样POST出去，供客户自有平台/邮件网关等消费
      local payload="$RAW_RESULT_JSON"
      local resp
      resp=$(curl -s -k --max-time 15 -X POST -H "Content-Type: application/json" -d "$payload" "$NOTIFY_WEBHOOK")
      log "通用Webhook推送返回: $resp"
      ;;
    *)
      warn "未知 NOTIFY_TYPE=$NOTIFY_TYPE，已跳过推送"
      ;;
  esac
}

# 组装markdown正文(钉钉/企微可用；飞书会自动去掉#标记)
build_msg_body() {
  local gate_line="$1"
  cat <<EOF
### ${SCAN_TITLE}
**应用**: ${APP_NAME}
**分支/提交**: ${GIT_BRANCH:-N/A} / ${GIT_COMMIT:-N/A} ${GIT_AUTHOR:+by ${GIT_AUTHOR}}
**缺陷统计**: 超危 **${SUPER_COUNT:-0}** | 高危 **${HIGH_COUNT:-0}** | 中危 **${MIDDLE_COUNT:-0}** | 低危 **${LOW_COUNT:-0}**
**门禁结论**: ${gate_line}
**报告**: PDF已存为 sast_report.pdf（流水线产物）
**平台**: ${SAST_URL} （任务名: ${APP_NAME}）
${BUILD_URL:+**构建详情**: [点击查看](${BUILD_URL})}
EOF
}

# ---------------------------------------------------------------------------
# 第1步: 打包源码 (排除列表可通过EXCLUDES覆盖)
# ---------------------------------------------------------------------------
PKG_FILE="codeai_upload.zip"
log "开始打包目录: $SCAN_DIR （排除: $EXCLUDES）"
cd "$SCAN_DIR" || die "进入扫描目录失败: $SCAN_DIR"
# 组装zip的-x参数（每项前加"*"通配，zip会按模式匹配）
zip_args=()
for e in $EXCLUDES; do zip_args+=(-x "*$e*" "*$e"); done
rm -f "$PKG_FILE"
zip -rq "$PKG_FILE" . "${zip_args[@]}" >/dev/null 2>&1
[ -f "$PKG_FILE" ] || die "打包失败，请检查SCAN_DIR目录是否为空或zip命令权限"
PKG_SIZE=$(du -h "$PKG_FILE" | cut -f1)
PKG_FILES=$(unzip -l "$PKG_FILE" | tail -1 | awk '{print $2}')
log "打包完成: $PKG_FILE ($PKG_SIZE, $PKG_FILES 个文件)"

# ---------------------------------------------------------------------------
# 第2步: 获取appId（复用 or 新建）
# ---------------------------------------------------------------------------
APP_ID=""
if [ "$APP_REUSE" = "1" ]; then
  # 按应用名在平台里查同名应用，查到就复用其appId → 版本对比/增量能力可延续
  log "查找平台已有同名应用: ${APP_NAME}"
  list_resp=$(sast_curl -G --url "${SAST_URL}/sast/api-v1/app/task/info" \
      --data-urlencode "pageNum=1" --data-urlencode "pageSize=50" \
      --data-urlencode "name=${APP_NAME}" --data-urlencode "isLike=true" \
      --data-urlencode "scanningModes=1,2" \
      -H "Sast-Token: ${SAST_TOKEN}")
  APP_ID=$(sast_jq "$list_resp" ".data.records[] | select(.taskName==\"${APP_NAME}\") | .appId" | head -n1)
  if [ -n "$APP_ID" ] && [ "$APP_ID" != "null" ]; then
    log "复用已有应用 appId=${APP_ID}"
  else
    log "未找到同名应用，将新建应用"
  fi
fi
if [ -z "$APP_ID" ] || [ "$APP_ID" = "null" ]; then
  gen_resp=$(sast_curl --request GET --url "${SAST_URL}/sast/api-v1/open-api/app/generate/id" \
      -H "Sast-Token: ${SAST_TOKEN}")
  gen_code=$(sast_jq "$gen_resp" '.code')
  if [ "$gen_code" != "0" ]; then
    [ "$BY_PASS" = "1" ] && { warn "获取应用ID失败(平台返回:$gen_resp)，已按BY_PASS策略放行"; exit 0; }
    die "获取应用ID失败: $gen_resp （请检查SAST_URL/SAST_TOKEN及平台服务状态）"
  fi
  APP_ID=$(sast_jq "$gen_resp" '.data')
  log "新建应用 appId=${APP_ID}"
fi

# ---------------------------------------------------------------------------
# 第3步: 提交检测任务 (用jq组装JSON，避免应用名带引号/中文导致JSON错乱)
# ---------------------------------------------------------------------------
log "提交检测任务到平台 ..."
add_task_json=$(jq -n \
  --arg app "$APP_NAME" --arg appid "$APP_ID" --arg desc "${SCAN_TITLE}" \
  --argjson autolang "$AUTO_LANGUAGE" --argjson apptype "$PROJECT_MODE" \
  --argjson projid "$PROJECT_ID" --argjson src "$TASK_SOURCE_TYPE" \
  --argjson detmode "$SCAN_MODE" \
  '{repositoryType:0, appType:$apptype, projectId:$projid, appId:$appid, appName:$app,
    autoLanguage:$autolang, appRuleList:[],
    whiteMethodsSetsId:"0", fileFilterSetsId:"0",
    taskSourceType:$src, detectionType:"1", scanningMode:$detmode,
    taintSetsId:"0", sensitiveSetsId:"0", sensitiveSetsName:"",
    taskConfig:{credibleSourceId:"0"}, description:$desc}')

submit_resp=$(sast_curl --request POST --url "${SAST_URL}/sast/api-v1/open-api/app/saveOrAgainTask" \
    -H "Sast-Token: ${SAST_TOKEN}" \
    -F "file=@${PKG_FILE}" \
    -F "addTaskJson=${add_task_json}")
submit_code=$(sast_jq "$submit_resp" '.code')
if [ "$submit_code" = "101104" ]; then
  # 平台规则: 同一应用不允许并发提交(上一次检测还在排队/检测中)。
  # 此时上一次的扫描任务正在平台上跑,直接进入轮询等待它出结果即可
  log "该应用已有排队中/检测中的任务(上一次构建提交的), 直接等待其结果"
elif [ "$submit_code" != "0" ]; then
  [ "$BY_PASS" = "1" ] && { warn "任务提交失败(平台返回:$submit_resp)，已按BY_PASS策略放行"; exit 0; }
  die "任务提交失败: $submit_resp （常见原因: 令牌失效/代码包过大/平台磁盘满）"
else
  log "任务提交成功，等待平台检测 (appId=${APP_ID})"
fi

# ---------------------------------------------------------------------------
# 第3.5步: 补发组件检测(SCA) —— Open API提交的任务平台不会自动发起组件检测,
# 若不调用此接口, 平台上该任务的组件检测会一直处于"未发起"状态
# (失败只告警不影响静态扫描; 组件检测结果在平台任务详情页查看)
# ---------------------------------------------------------------------------
if [ "$SCA_ENABLED" = "1" ]; then
  sca_resp=$(sast_curl --request POST --url "${SAST_URL}/sast/api-v1/app/executeScaAgain" \
      -H "Sast-Token: ${SAST_TOKEN}" -H "Content-Type: application/json" \
      -d "{\"appId\": \"${APP_ID}\", \"appName\": \"${APP_NAME}\"}")
  sca_code=$(sast_jq "$sca_resp" '.code')
  if [ "$sca_code" = "0" ]; then
    log "组件检测(SCA)已发起"
  else
    warn "组件检测发起失败(不影响静态扫描, 平台上也可手动'发起组件检测'): $sca_resp"
  fi
fi

# ---------------------------------------------------------------------------
# 异步模式出口: WAIT_RESULT=0 时提交成功即结束, 不等待检测结果
# (流水线不被扫描阻塞; 推送"已提交"通知并附平台跳转链接, 用户登录平台看进度和结果)
# ---------------------------------------------------------------------------
if [ "$WAIT_RESULT" = "0" ]; then
  rm -f "$PKG_FILE"
  log "异步模式(WAIT_RESULT=0): 任务已提交, 不等待结果。appId=${APP_ID}"
  # 推送"已提交"通知(含平台链接), 用户点链接登录平台即可查看扫描进度与结果
  ASYNC_BODY=$(cat <<EOF
### CodeAI扫描已提交
**应用**: ${APP_NAME}
**分支/提交**: ${GIT_BRANCH:-N/A} / ${GIT_COMMIT:-N/A} ${GIT_AUTHOR:+by ${GIT_AUTHOR}}
**状态**: 检测进行中, 完成时间以平台为准
**结果查看**: ${SAST_URL}/detection/code （登录平台后搜索应用名 ${APP_NAME}）
EOF
)
  notify_send "CodeAI扫描已提交·${APP_NAME}" "$ASYNC_BODY" "$NOTIFY_AT"
  log "检测结果请登录平台查看: ${SAST_URL} → 代码审计 → ${APP_NAME}"
  exit 0
fi

# ---------------------------------------------------------------------------
# 第4步: 轮询任务结果 (状态: 1排队 2检测中 3完成 0失败)
# ---------------------------------------------------------------------------
TASK_ID=""
status=""
start_ts=$(date +%s)
while :; do
  sleep "$POLL_INTERVAL"
  result_resp=$(sast_curl --request GET \
      --url "${SAST_URL}/sast/api-v1/open-api/defect/jenkins/result?appId=${APP_ID}" \
      -H "Sast-Token: ${SAST_TOKEN}")
  status=$(sast_jq "$result_resp" '.data.status')
  TASK_ID=$(sast_jq "$result_resp" '.data.taskId')
  elapsed=$(( $(date +%s) - start_ts ))
  case "$status" in
    3) log "检测完成 (耗时${elapsed}s, taskId=${TASK_ID})"; break ;;
    0) [ "$BY_PASS" = "1" ] && { warn "平台任务失败(状态0)，已按BY_PASS策略放行"; exit 0; }
       die "平台检测任务失败，可登录平台查看任务日志排查" ;;
    *) log "检测中... 已等待${elapsed}s (状态=${status})" ;;
  esac
  if [ $(( elapsed / 60 )) -ge "$TIMEOUT_MINUTES" ]; then
    if [ "$BY_PASS" = "1" ]; then
      warn "等待超过${TIMEOUT_MINUTES}分钟，已按BY_PASS策略放行（可调大TIMEOUT_MINUTES）"
      exit 0
    else
      die "等待超时(${TIMEOUT_MINUTES}分钟)"
    fi
  fi
done

# 汇总各级缺陷数（openJenkinsFlawInfoMap按BUG/VULNERABILITY/CODE_SMELL分类，逐项相加）
SUPER_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].superCount] | add // 0')
HIGH_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].highCount] | add // 0')
MIDDLE_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].middleCount] | add // 0')
LOW_COUNT=$(sast_jq "$result_resp" '[.data.openJenkinsFlawInfoMap[].lowCount] | add // 0')
log "缺陷统计: 超危=${SUPER_COUNT} 高危=${HIGH_COUNT} 中危=${MIDDLE_COUNT} 低危=${LOW_COUNT}"

# ---------------------------------------------------------------------------
# 第5步: 生成并下载PDF报告 (reportType=1 概览报告；2为详细报告)
# ---------------------------------------------------------------------------
log "生成检测报告..."
enc_name=$(urlencode "${APP_NAME}")
report_resp=$(sast_curl --request GET \
    --url "${SAST_URL}/sast/api-v1/open-api/defect/blue/generate/report?reportType=1&taskId=${TASK_ID}&reportName=${enc_name}&appId=${APP_ID}" \
    -H "Sast-Token: ${SAST_TOKEN}")
REPORT_ID=$(sast_jq "$report_resp" '.data')
if [ -z "$REPORT_ID" ] || [ "$REPORT_ID" = "null" ]; then
  warn "报告创建失败(平台返回:$report_resp)，跳过报告下载"
else
  log "报告生成中 (reportId=${REPORT_ID})"
  r_status=""
  r_start=$(date +%s)
  while [ "$r_status" != "2" ]; do
    sleep 5
    r_status=$(sast_curl --request GET \
        --url "${SAST_URL}/sast/api-v1/open-api/defect/blue/generate/report/status?reportId=${REPORT_ID}" \
        -H "Sast-Token: ${SAST_TOKEN}" | jq -r '.data.status' 2>/dev/null)
    if [ $(( $(date +%s) - r_start )) -gt 300 ]; then warn "报告生成超时(5分钟)，跳过下载"; break; fi
  done
  if [ "$r_status" = "2" ]; then
    sast_curl --request GET \
        --url "${SAST_URL}/sast/api-v1/open-api/defect/blue/download/report?reportId=${REPORT_ID}" \
        -H "Sast-Token: ${SAST_TOKEN}" -o "${REPORT_DIR}/sast_report.pdf"
    log "PDF报告已下载: ${REPORT_DIR}/sast_report.pdf"
  fi
fi

# ---------------------------------------------------------------------------
# 第6步: 质量门禁判定 + 推送通知
# ---------------------------------------------------------------------------
GATE_RESULT="未启用(仅告警)"
if [ "$GATE_ENABLED" = "1" ]; then
  if [ "${SUPER_COUNT:-0}" -gt "$GATE_SUPER" ] || [ "${HIGH_COUNT:-0}" -gt "$GATE_HIGH" ] \
     || [ "${MIDDLE_COUNT:-0}" -gt "$GATE_MIDDLE" ] || [ "${LOW_COUNT:-0}" -gt "$GATE_LOW" ]; then
    GATE_RESULT="⛔ 不通过"
  else
    GATE_RESULT="✅ 通过"
  fi
fi

# 组装推送内容并推送（推送失败不影响主流程）
MSG_BODY=$(build_msg_body "$GATE_RESULT")

# 结构化结果JSON（NOTIFY_TYPE=raw 时推送给客户自有平台的报文格式）
RAW_RESULT_JSON=$(jq -n \
  --arg app "$APP_NAME" --arg taskid "$TASK_ID" --arg appid "$APP_ID" \
  --arg title "$SCAN_TITLE" --arg gate "$GATE_RESULT" --arg url "$SAST_URL" \
  --arg branch "$GIT_BRANCH" --arg author "$GIT_AUTHOR" --arg commit "$GIT_COMMIT" \
  --arg build "$BUILD_URL" --arg time "$(date '+%Y-%m-%d %H:%M:%S')" \
  --argjson sup "${SUPER_COUNT:-0}" --argjson high "${HIGH_COUNT:-0}" \
  --argjson mid "${MIDDLE_COUNT:-0}" --argjson low "${LOW_COUNT:-0}" \
  '{scanTitle:$title, appName:$app, branch:$branch, author:$author, commit:$commit,
    platformUrl:$url, appId:$appid, taskId:$taskid, scanTime:$time,
    defectCount:{super:$sup, high:$high, middle:$mid, low:$low},
    gateResult:$gate, buildUrl:$build}')

# 结果JSON落盘（供 gitee-report.sh 回写Gitee commit状态/MR评论消费）
if [ -n "$RESULT_JSON_FILE" ]; then
  echo "$RAW_RESULT_JSON" > "$RESULT_JSON_FILE" 2>/dev/null || true
fi
notify_send "${SCAN_TITLE}·${APP_NAME}" "$MSG_BODY" "$NOTIFY_AT"

# 同时把结构化结果输出到控制台（CI日志里一眼可见）和RAW_RESULT_JSON(供raw webhook用)
echo "======================================================"
echo "  灵脉CodeAI 扫描结果   appId=${APP_ID}  taskId=${TASK_ID}"
echo "  超危: ${SUPER_COUNT}   高危: ${HIGH_COUNT}   中危: ${MIDDLE_COUNT}   低危: ${LOW_COUNT}"
echo "  质量门禁: ${GATE_RESULT}"
echo "  平台地址: ${SAST_URL}"
echo "======================================================"

# 清理临时包
rm -f "$PKG_FILE"

# 门禁不通过 → 退出码1 → CI流水线置红
if [ "$GATE_ENABLED" = "1" ] && [ "$GATE_RESULT" = "⛔ 不通过" ]; then
  echo "$LOG_PREFIX 质量门禁不通过: 超危>${GATE_SUPER} 高危>${GATE_HIGH} 中危>${GATE_MIDDLE} 低危>${GATE_LOW}"
  exit 1
fi
exit 0
