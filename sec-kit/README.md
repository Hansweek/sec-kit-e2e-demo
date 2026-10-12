# govee-sec-kit · 研发安全工具链 CI 对接工具包

> 首次交付：2026-10-09 智岩科技（Govee）。设计目标：**换客户只改一个文件**。
> 场景依据：《Goovee 研发安全工具链集成 SOP 流程图（初稿）2026.9.24》四场景。

## 目录结构

```
govee-sec-kit/
├── config.env.example            ← 换客户唯一要改的文件（地址/令牌/门禁/钉钉/超时）
├── bin/
│   ├── codeai-incremental-scan.sh   ← CodeAI 主脚本：push增量/tag全量/定时强制全量+门禁+PDF报告+钉钉
│   ├── codeai-scan.sh               ← CodeAI 备用简化版：全量扫（增量脚本故障时的兜底）
│   └── sca-scan.sh                  ← SCA 单文件全流程：provision/deps/build/artifact/report/upload
├── ci/                              ← 各 CI 平台"薄封装"（无逻辑无密钥，只做触发+变量注入）
│   ├── github-actions/security-scan.yml   ← Govee 嵌入式+后端仓库用（PR/push/tag/定时/手动）
│   ├── gitlab/.gitlab-ci.yml              ← GitLab 类客户模板
│   └── yunxiao/
│       ├── yunxiao-security-step.sh       ← 云效统一接入步骤（SAST+SCA 一条命令，与 GitHub 封装同契约）
│       └── 云效Flow接入指南.md             ← Govee ERP 流水线（阿里云效）界面配置指南
└── docs/现场作业单.md                ← 2026-10-09 现场执行清单与验证记录表
```

## 脚本能力速查

| 脚本 | 用法 | 能力 |
|---|---|---|
| `codeai-incremental-scan.sh` | 配好环境变量直接执行 | 按应用名复用应用；平台基线 hash + git diff 增量；101104 并发保护自动等待；排队超时 BY_PASS 放行；门禁阈值阻断；PDF 报告；钉钉(加签)/企微/飞书/raw 推送；退出码 0/1/2 |
| `sca-scan.sh deps` | 组件依赖扫描（源码特征文件） | 项目自动建/复用；红线卡点(基线/黑白名单)；结果 JSON 落盘；钉钉推送 |
| `sca-scan.sh artifact` | 制品/固件二进制成分扫描 | `SCAN_DIR`+`SCAN_PATTERNS` 控制范围，嵌入式场景用 |
| `sca-scan.sh report` | 报告生成+下载 | 需 `SCA_APP_ID`（deps/artifact 模式自动获取后落盘） |
| `codeai-scan.sh` | 全量扫描兜底 | 与增量脚本同一套 OpenAPI，无增量逻辑，故障时替换使用 |

## 快速开始（现场冒烟）

```bash
cp config.env.example config.env && vi config.env   # 填平台地址与令牌
source config.env
cd <某试点仓库>
bash <kit路径>/bin/sca-scan.sh provision            # 建或复用 SCA 项目(落盘 provision.env，deps 的前置必跑)
source ./provision.env
bash <kit路径>/bin/sca-scan.sh deps                 # 组件依赖扫描
bash <kit路径>/bin/codeai-incremental-scan.sh       # CodeAI 首次全量
# 连续改一行代码再执行一次 → 观察日志出现"存在变更文件 → 增量扫描"即为增量链路打通
```

云效 Flow 接入：仓库根放入 `sec-kit/`，流水线"自定义 Shell"步骤执行
`bash sec-kit/ci/yunxiao/yunxiao-security-step.sh`（SAST+SCA 一次跑完，按仓库名自动建/复用项目），
界面配置（两条流水线/变量表/产物归档/FAQ）见 `ci/yunxiao/云效Flow接入指南.md`。

## 换客户复用三步法

1. 复制整个 `govee-sec-kit/` 目录；
2. 改 `config.env.example`（平台地址、令牌、应用命名前缀、门禁阈值、钉钉群、超时）；
3. 按客户 CI 平台取 `ci/` 下对应薄封装（GitHub Actions / GitLab / 云效 / Jenkins 片段），新平台照抄一个——封装里没有任何客户差异。

密钥注入优先级：CI 变量（推荐，Masked）> `source config.env`。令牌永不进仓库、永不进脚本。

## 安全边界说明

- `sca-scan.sh` 的 `BUILD_CMD` 是**流水线负责人专用的构建命令扩展钩子**（脚本头注释第 33 行），只从环境变量读取，脚本不会把任何平台响应或仓库内容写入该变量。仅允许在 config/CI 变量中由流水线属主手工设置，禁止从不可信输入（PR 内容、API 响应等）派生——它与 CI 的 shell 步骤同信任级。
- 令牌类变量（SAST_TOKEN/SCA_USER_TOKEN/SCA_PROJECT_TOKEN/NOTIFY_WEBHOOK 等）一律走 CI Variables（Masked）或 config.env（.gitignore），本包所有文件均不含客户凭据。
- 已知行为差异（审核结论，冻结不动脚本）：① `sca-scan.sh` 的 `deps/artifact` 硬性要求 SCA_PROJECT_TOKEN（第 178 行校验），封装已内置 `provision` 前置步骤；② `sca-scan.sh` 通知不支持钉钉加签——机器人统一用"自定义关键词"模式（见 config.env.example 通知节）；③ `DEPS_GATE/ARTIFACT_GATE` 缺省=1，灰度期必须在 CI 显式配 0；④ `sca-scan.sh` 严格模式 bypass_fail 退出码为 3（脚本头文档只写了 0/1/2）。
