#!/usr/bin/env bash
# ============================================================================
#  云效 Flow 统一安全扫描步骤 (yunxiao-security-step.sh) · SAST+SCA 一条命令
# ----------------------------------------------------------------------------
#  定位: 阿里云效 Flow"自定义Shell步骤"适配层——与 GitHub Actions 封装同契约，
#        只做"云效环境变量 → sec-kit 变量"的翻译与编排，不含业务逻辑与密钥。
#  用法: 仓库根放入 sec-kit/，流水线添加"自定义 Shell"步骤执行:
#          bash sec-kit/ci/yunxiao/yunxiao-security-step.sh
#  云效变量配置(流水线 → 变量与缓存, 敏感项勾"私密"):
#    【必填】SAST_URL  SAST_TOKEN(私密)  SAST_USERNAME
#            SCA_URL   SCA_USER_TOKEN(私密)
#    【推荐】NOTIFY_WEBHOOK(私密) NOTIFY_SECRET(私密,钉钉加签) NOTIFY_TYPE
#            SECURITY_GATE(0/1 总开关) 或 SAST_GATE/SCA_DEPS_GATE 分开关
#            SBOM_TYPES(默认"spdx vex")  TLS_INSECURE(默认0)
#    【可选】ENABLE_SAST=0 / ENABLE_SCA=0 单独关闭
#            ENABLE_SCA_ARTIFACT=1 + SCAN_PATTERNS(嵌入式制品扫描)
#            PROJECT_MEMBERS(协作人用户名逗号分隔, 平台无云效组织API时的手工口径)
#  云效内置变量(脚本自动消费,缺省回退 git): CI_COMMIT_REF_NAME CI_COMMIT_ID
#    CI_COMMIT_MESSAGE CI_BUILD_NUMBER CI_PIPELINE_NAME CI_JOB_NAME
#  归档: 产物落在 sec-results/ 与 sast_report.pdf —— 流水线"构建产物"步骤
#        勾选路径 sec-results/** 与 sast_report.pdf 即自动归档。
#  退出码: 0=全部通过/放行  1=门禁不通过  2=环境错误  3=SCA严格模式平台异常
# ============================================================================
set -uo pipefail
KIT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"   # sec-kit 根
LOG_PREFIX="[YUNXIAO]"
log()  { echo "$LOG_PREFIX $(date '+%H:%M:%S') $*"; }
warn() { echo "$LOG_PREFIX [警告] $*" >&2; }

# ---------------- ① 云效内置变量 → 统一仓库身份 ----------------
# 云效: CI_COMMIT_REF_NAME=分支或tag, CI_COMMIT_ID=commit sha; 缺省从 git 推导
GIT_BRANCH_NAME="${CI_COMMIT_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo master)}"
GIT_COMMIT_SHA="${CI_COMMIT_ID:-$(git rev-parse HEAD 2>/dev/null || echo '')}"
GIT_MSG_HEAD=$(printf '%s' "${CI_COMMIT_MESSAGE:-$(git log -1 --format=%s 2>/dev/null || echo '')}" | head -c 60)
_repo_url=$(git config --get remote.origin.url 2>/dev/null || echo '')
REPO_NAME=$(basename "${_repo_url%.git}" 2>/dev/null); [ -n "$REPO_NAME" ] || REPO_NAME="${CI_REPOSITORY_NAME:-yunxiao-app}"
# tag 判定: 云效 tag 触发时 CI_COMMIT_REF_NAME 即 tag 名(无法精确区分, 以 refs 前缀/构建上下文兜底)
CI_COMMIT_TAG=""
case "$GIT_BRANCH_NAME" in
  refs/tags/*) CI_COMMIT_TAG="${GIT_BRANCH_NAME#refs/tags/}" ;;
esac
# 分支名中的 / 转义(应用名规则与 GitHub 侧一致: 仓库名-分支名)
SAFE_BRANCH=$(printf '%s' "$GIT_BRANCH_NAME" | tr '/ ' '__')
APP_NAME="${REPO_NAME}-${SAFE_BRANCH}"
BUILD_URL="云效流水线 ${CI_PIPELINE_NAME:-} #${CI_BUILD_NUMBER:-} (job: ${CI_JOB_NAME:-})"
log "仓库=${REPO_NAME} 分支=${GIT_BRANCH_NAME} 提交=${GIT_COMMIT_SHA:0:12} 应用=${APP_NAME}"

# ---------------- ② 门禁开关解析(两级: 组件变量 > 总开关) ----------------
_gnorm() { case "${1:-}" in 1|true|True|TRUE|y|Y|yes) echo 1;; 0|false|False|FALSE|n|N|no) echo 0;; *) echo "";; esac; }
_gres()  { _c=$(_gnorm "$2"); if [ -n "$_c" ]; then echo "$_c"; else _g=$(_gnorm "$1"); [ -n "$_g" ] && echo "$_g" || echo 0; fi; }
export GATE_ENABLED=$(_gres "${SECURITY_GATE:-}" "${SAST_GATE:-}")
export DEPS_GATE=$(_gres "${SECURITY_GATE:-}" "${SCA_DEPS_GATE:-}")
export ARTIFACT_GATE=$(_gres "${SECURITY_GATE:-}" "${SCA_ARTIFACT_GATE:-}")
log "门禁: SAST=${GATE_ENABLED} SCA依赖=${DEPS_GATE} SCA制品=${ARTIFACT_GATE} (1=阻断 0=仅告警)"

# ---------------- ②½ 必填变量集中预检(缺什么一次说清, 不让用户跑到深处才报错) ----------------
_missing=""
if [ "${ENABLE_SAST:-1}" != "0" ]; then
  [ -n "${SAST_URL:-}" ]   || _missing="${_missing} SAST_URL"
  [ -n "${SAST_TOKEN:-}" ] || _missing="${_missing} SAST_TOKEN"
  [ -n "${SAST_USERNAME:-}" ] || warn "未配 SAST_USERNAME: 项目经理/归属部门将回退默认值, 推荐配置令牌归属人用户名"
fi
if [ "${ENABLE_SCA:-1}" != "0" ]; then
  [ -n "${SCA_URL:-}" ]        || _missing="${_missing} SCA_URL"
  [ -n "${SCA_USER_TOKEN:-}" ] || _missing="${_missing} SCA_USER_TOKEN"
fi
if [ -n "$_missing" ]; then
  echo "$LOG_PREFIX [错误] 以下必填变量未配置:${_missing}"
  echo "$LOG_PREFIX [错误] 请到 云效流水线-变量与缓存 中配置(敏感项勾私密), 说明见 ci/yunxiao/云效Flow接入指南.md"
  exit 2
fi

# ---------------- ③ 依赖自检 ----------------
for c in curl jq zip git python3; do
  command -v "$c" >/dev/null 2>&1 || warn "执行机缺少 [$c]，部分能力(报告解包/缺陷导出)将降级"
done
command -v curl >/dev/null 2>&1 || { echo "$LOG_PREFIX [错误] 缺少 curl，无法执行扫描"; exit 2; }
mkdir -p sec-results

# ---------------- ④ SAST: 灵脉CodeAI(增量) ----------------
SAST_EXIT=0
if [ "${ENABLE_SAST:-1}" != "0" ] && [ -n "${SAST_URL:-}" ]; then
  log "==== 灵脉CodeAI SAST 扫描开始 ===="
  env \
    SAST_URL="$SAST_URL" SAST_TOKEN="$SAST_TOKEN" \
    SAST_PROJECT_NAME="${SAST_PROJECT_NAME:-$REPO_NAME}" \
    SAST_USERNAME="${SAST_USERNAME:-}" \
    SAST_PROJECT_MEMBERS="${PROJECT_MEMBERS:-}" \
    APP_NAME="$APP_NAME" \
    GIT_BRANCH="$GIT_BRANCH_NAME" GIT_COMMIT="$GIT_COMMIT_SHA" \
    GIT_AUTHOR="${CI_COMMITTER_NAME:-云效流水线}" \
    BUILD_URL="$BUILD_URL" \
    FORCE_FULL="${FORCE_FULL:-0}" CI_COMMIT_TAG="$CI_COMMIT_TAG" \
    GATE_ENABLED="$GATE_ENABLED" \
    GATE_SUPER="${GATE_SUPER:-0}" GATE_HIGH="${GATE_HIGH:-0}" \
    GATE_MIDDLE="${GATE_MIDDLE:-0}" GATE_LOW="${GATE_LOW:-0}" \
    BY_PASS="${BY_PASS:-1}" BY_PASS_TIMEOUT_MINUTES="${BY_PASS_TIMEOUT_MINUTES:-60}" \
    TLS_INSECURE="${TLS_INSECURE:-0}" \
    SAST_REPORT_KIND="${SAST_REPORT_KIND:-DEFECT}" \
    EXPORT_DEFECTS="${EXPORT_DEFECTS:-1}" \
    EXPORT_DIR="$PWD/sec-results" REPORT_DIR="$PWD" \
    RESULT_JSON_FILE="$PWD/sec-results/codeai-result.json" \
    NOTIFY_WEBHOOK="" \
    bash "$KIT_DIR/bin/codeai-incremental-scan.sh" || SAST_EXIT=$?
  log "SAST 退出码=${SAST_EXIT}"
else
  log "ENABLE_SAST=0 或未配 SAST_URL → 跳过 SAST"
fi

# ---------------- ⑤ SCA: 源鉴SCA(项目自动纳管+依赖扫描+SBOM/VEX) ----------------
SCA_EXIT=0
if [ "${ENABLE_SCA:-1}" != "0" ] && [ -n "${SCA_URL:-}" ]; then
  log "==== 源鉴SCA 扫描开始 ===="
  (
    set -e
    export SCA_URL SCA_USER_TOKEN
    export SCA_PROJECT_NAME="${SCA_PROJECT_NAME:-$REPO_NAME}"
    export SCA_USERNAME="${SCA_USERNAME:-${SAST_USERNAME:-}}"
    export SCA_PROJECT_MEMBERS="${PROJECT_MEMBERS:-}"
    export APP_NAME GIT_BRANCH="$GIT_BRANCH_NAME" GIT_COMMIT="$GIT_COMMIT_SHA"
    export DEPS_GATE BY_PASS="${BY_PASS:-1}" TIMEOUT_MINUTES="${TIMEOUT_MINUTES:-90}"
    export TLS_INSECURE="${TLS_INSECURE:-0}"
    export AUTO_SBOM="${AUTO_SBOM:-1}" SBOM_TYPES="${SBOM_TYPES:-spdx vex}"
    export RESULT_JSON_FILE="$PWD/sec-results/sca-result.json"
    export OUT_DIR="$PWD/sec-results"
    bash "$KIT_DIR/bin/sca-scan.sh" provision
    source ./provision.env
    bash "$KIT_DIR/bin/sca-scan.sh" deps
    # 检测报告(Excel)
    if [ -f sec-results/sca-result.json ] && command -v jq >/dev/null 2>&1; then
      export SCA_APP_ID="$(jq -r '.appId // empty' sec-results/sca-result.json)"
      export TASK_ID="$(jq -r '.taskId // empty' sec-results/sca-result.json)"
      [ -n "${SCA_APP_ID:-}" ] && bash "$KIT_DIR/bin/sca-scan.sh" report || true
    fi
    # 制品扫描(嵌入式, 变量门控)
    if [ "${ENABLE_SCA_ARTIFACT:-0}" = "1" ] && [ -n "${SCAN_PATTERNS:-}" ]; then
      export ARTIFACT_GATE RESULT_JSON_FILE="$PWD/sec-results/sca-result-artifact.json"
      bash "$KIT_DIR/bin/sca-scan.sh" artifact || true
    fi
  ) || SCA_EXIT=$?
  log "SCA 退出码=${SCA_EXIT}"
else
  log "ENABLE_SCA=0 或未配 SCA_URL → 跳过 SCA"
fi

# ---------------- ⑥ 统一聚合通知(钉钉/企微/飞书, 支持加签) ----------------
if [ -n "${NOTIFY_WEBHOOK:-}" ]; then
  RESULT_DIR="$PWD/sec-results" \
  NOTIFY_WEBHOOK="$NOTIFY_WEBHOOK" NOTIFY_TYPE="${NOTIFY_TYPE:-dingtalk}" \
  NOTIFY_SECRET="${NOTIFY_SECRET:-}" NOTIFY_AT="${NOTIFY_AT:-}" \
  TLS_INSECURE="${TLS_INSECURE:-0}" BUILD_URL="$BUILD_URL" \
    bash "$KIT_DIR/bin/sec-notify.sh" || warn "聚合通知发送未确认成功(不影响扫描结论)"
else
  log "未配置 NOTIFY_WEBHOOK，跳过聚合通知"
fi

# ---------------- ⑦ 汇总退出码(门禁不通过优先透传) ----------------
log "==== 扫描编排结束 SAST=${SAST_EXIT} SCA=${SCA_EXIT} ===="
ls -la sec-results/ 2>/dev/null || true
[ "$SAST_EXIT" = "1" ] || [ "$SCA_EXIT" = "1" ] && exit 1
[ "$SAST_EXIT" = "2" ] || [ "$SCA_EXIT" = "2" ] && exit 2
exit 0
