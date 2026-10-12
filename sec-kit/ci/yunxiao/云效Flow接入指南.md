# 云效 Flow 接入指南（阿里云效 · 自定义 Shell 步骤）

> 适用：代码库托管在**阿里云效 Codeup**、流水线使用**云效 Flow** 的部门（如 ERP）。
> 能力与 GitHub 版完全一致：SAST 增量扫描 / SCA 依赖+制品扫描 / 项目自动纳管（项目经理=令牌归属人、
> 归属部门、仓库成员）/ 详情报告+全跟踪路径 / SBOM(SPDX)+VEX 归档 / 钉钉聚合通知（支持加签）。
> 核心：仓库根放 `sec-kit/`，流水线加一步 `bash sec-kit/ci/yunxiao/yunxiao-security-step.sh`。

## 一、放文件（仓库管理员，5 分钟）

把交付包 `sec-kit/` 整个目录复制到仓库根并提交（纯脚本、无任何密钥，可直接入库）。

## 二、建流水线（10 分钟）

建议两条流水线（与 GitHub 版触发面对齐）：

| 流水线 | 代码源触发 | 作用 |
|---|---|---|
| 主流水线 | **提交/合并请求触发**（目标分支=默认分支） | 提交即扫：push 增量、MR 卡点 |
| 定时巡检 | 不配代码源触发，用**定时触发**（如每天 09:30） | 强制全量巡检默认分支 |

每条流水线添加步骤：**构建 → 自定义 Shell**（或"空任务"步骤里的 Shell 执行），命令：

```bash
bash sec-kit/ci/yunxiao/yunxiao-security-step.sh
```

> 云效托管构建机需能访问 CodeAI/SCA 平台地址与钉钉 webhook；自建构建机同理。
> 步骤环境镜像选含 `curl jq zip python3 git` 的通用镜像（阿里云自带镜像均满足）。

## 三、配变量（流水线 → 变量与缓存，敏感项勾"私密"）

**必填 5 项**：

| 变量 | 值 | 私密 |
|---|---|---|
| `SAST_URL` | CodeAI 平台地址（结尾不带 /） | |
| `SAST_TOKEN` | CodeAI 个人中心→访问令牌 | ✔ |
| `SAST_USERNAME` | 令牌归属人平台用户名（自动设为项目经理/归属其部门） | |
| `SCA_URL` | SCA 平台地址（必须带 :30001 端口） | |
| `SCA_USER_TOKEN` | SCA 个人中心→访问令牌 | ✔ |

**推荐配置**：

| 变量 | 值 | 说明 |
|---|---|---|
| `NOTIFY_WEBHOOK` | 钉钉群机器人 Webhook（✔私密） | 流水线末尾自动推**聚合卡片**（SAST+SCA+SBOM 一条消息） |
| `NOTIFY_SECRET` | 钉钉"加签"密钥（✔私密） | v2 聚合通知支持加签，机器人安全模式任选 |
| `SCA_USERNAME` | SCA 令牌归属人用户名 | 不配时继承 SAST_USERNAME（同名时配一个即可） |
| `PROJECT_MEMBERS` | 协作人用户名（逗号分隔） | 云效无组织成员开放 API，成员清单手工维护（季度核对一次）；平台项目成员还会按归属部门全员可见 |

**按需**：`SECURITY_GATE`(门禁总开关)/`SAST_GATE`/`SCA_DEPS_GATE`、`SBOM_TYPES`(默认 `spdx vex`)、
`ENABLE_SCA_ARTIFACT=1`+`SCAN_PATTERNS`(嵌入式制品扫描)、`TLS_INSECURE=1`(自签证书)、
`ENABLE_SAST=0`/`ENABLE_SCA=0`(单独停某路)。

## 四、产物归档（每条流水线，2 分钟）

流水线添加 **构建 → 构建产物** 步骤，勾选/填写路径：

```
sec-results/**
sast_report.pdf
```

跑完后在流水线"产物"处可下载：详情报告 PDF、全缺陷+跟踪路径（JSON/HTML）、SPDX SBOM、VEX、Excel 检测报告。

## 五、首次验证（照做即通）

1. 向默认分支提一个 commit → 主流水线自动运行 → 步骤日志出现 `灵脉CodeAI SAST 扫描开始` 与 `源鉴SCA 扫描开始`
2. 跑完检查产物（见上）与钉钉聚合卡片
3. 再提一个 commit → 日志出现 **"存在变更文件 → 增量扫描"** 即增量链路生效
4. 平台核对：CodeAI/SCA 项目管理出现以仓库名命名的项目（项目经理=令牌归属人，部门=归属人部门）

## 六、常见问题

| 现象 | 处理 |
|---|---|
| 日志"缺少 curl/jq" | 构建镜像太精简——换通用镜像，或在步骤命令最前加安装行 |
| 云效变量在脚本里读不到 | 确认配在"变量与缓存"且名称全大写一致；私密变量勾选了"私密" |
| tag 触发想全量 | 步骤前置变量 `FORCE_FULL=1`，或依赖脚本对 `refs/tags/` 前缀的自动识别 |
| 门禁想先只告警 | 不配 `SECURITY_GATE`（默认 0=只告警），观察 1–2 周再开 |
| 与平台生成的 aliyun.sh 冲突 | 同一流水线**二选一**挂载（会重复扫描）；sec-kit 为完整版，aliyun.sh 仅作无 sec-kit 时的轻量兜底 |
| 需要手动验证 | 构建机执行 §三 同名环境变量 + `bash sec-kit/bin/codeai-incremental-scan.sh`，成功则链路正常 |

## 七、变量对照（云效 ↔ GitHub 版）

| 能力 | GitHub | 云效 |
|---|---|---|
| 平台地址 | vars.CODEAI_URL / SCA_URL | SAST_URL / SCA_URL |
| 令牌 | secrets.CODEAI_TOKEN / SCA_USER_TOKEN | SAST_TOKEN / SCA_USER_TOKEN（私密） |
| 令牌归属人 | vars.SAST_USERNAME / SCA_USERNAME | SAST_USERNAME / SCA_USERNAME |
| 成员清单 | 自动拉 collaborators（PAT 兜底） | PROJECT_MEMBERS 手工清单 |
| 门禁 | SECURITY_GATE+组件级 | SECURITY_GATE 或 SAST_GATE/SCA_DEPS_GATE |
| 通知 | secrets.NOTIFY_* | NOTIFY_*（私密勾选） |
| 分支/提交 | github.* 上下文 | CI_COMMIT_REF_NAME / CI_COMMIT_ID（脚本自动消费，缺省回退 git） |
