# govee-sec-kit · 研发安全工具链 CI 对接工具包 v2

> 首次交付：2026-10-09 智岩科技（Govee）。v2：2026-10-12（真实环境全链路实测）。
> 设计目标：**换客户只改一个文件**（`config.env.example` → 全部差异项与 CI 变量对照）。

## v2 新增能力（均已实测）

| # | 能力 | 说明 |
|---|---|---|
| 1 | SAST **详情报告** | `reportComponent=DEFECT`（概要报告不再作为默认产物） |
| 2 | **全缺陷+全跟踪路径**归档 | `defect/issue`（数量不限自动翻页）+ 逐缺陷污点链（来源→跟踪→爆发点），产出 JSON + 可读 HTML |
| 3 | **SBOM(SPDX 2.3) + VEX(CSAF 2.0)** | SCA 扫描完成自动导出并随流水线归档（可加 CycloneDX） |
| 4 | **项目自动纳管 v2** | 项目名=仓库名；**项目经理=令牌归属人**、**归属部门=归属人部门**（按 `SAST_USERNAME`/`SCA_USERNAME` 解析）；**仓库协作人→项目成员**（GitHub 自动拉取 collaborators，三级降级：GITHUB_TOKEN→只读PAT→手工清单） |
| 5 | **SAST 增量扫描** | 应用复用（项目维度检索）→ 平台基线 hash ↔ git diff → `incrementSwitch=1` 只扫变更文件 |
| 6 | **钉钉聚合通知** | 自搓 webhook（`sec-notify.sh`）：一张卡片汇总 SAST 四色统计+TOP高危缺陷定位、SCA 组件/漏洞统计+红线、SBOM/VEX 产物、报告直达链接；**支持加签**；默认仅门禁阻断时@人 |
| 7 | **SAST/SCA 并行** | GitHub Actions 拆双 job 并行 + report job 聚合归档，流水线墙钟=max(两路) 而非 sum |

## 目录结构

```
govee-sec-kit/
├── config.env.example            ← 换客户唯一要改的文件（v2 全变量 + ▲必填6项 + 三平台变量对照）
├── bin/                          ← 核心脚本（平台无关，GitHub 与云效执行同一份文件）
│   ├── codeai-incremental-scan.sh   ← CodeAI: 增量感知+项目纳管v2+详情报告+全缺陷跟踪导出+门禁
│   ├── sca-scan.sh                  ← SCA: 项目纳管v2+依赖/制品扫描+红线+任务统计+报告+SBOM/VEX自动导出
│   ├── sca-sbom.sh                  ← SBOM+VEX 专用导出（SPDX/CycloneDX/CSAF，OpenAPI直连）
│   ├── sec-notify.sh                ← 聚合通知（钉钉加签/企微/飞书，一张卡片）
│   └── codeai-scan.sh               ← CodeAI 全量兜底（增量脚本故障时替换用）
├── ci/                           ← 各 CI 平台"薄封装"（无逻辑无密钥，只做触发+变量注入）
│   ├── github-actions/security-scan.yml   ← 双job并行+report聚合（PR/push/tag/定时/手动）
│   └── yunxiao/
│       ├── yunxiao-security-step.sh       ← 云效统一接入步骤（SAST+SCA+通知一条命令）
│       └── 云效Flow接入指南.md             ← 云效界面配置指南
└── docs/
    ├── 客户使用指引.md                    ← 管理员一页纸速查（GitHub 为主，通用口径）
    ├── 参数映射与设计说明.md              ← CI参数→统一契约→平台API 全映射（v2接口依据与实测结论）
    ├── 灵脉CodeAI×源鉴SCA对接GitHub操作指引V1.0.docx  ← 详细版
```

## 脚本能力速查

| 脚本 | 用法 | 能力 |
|---|---|---|
| `codeai-incremental-scan.sh` | 配好环境变量直接执行 | 按应用名复用应用（项目维度检索）；平台基线 hash + git diff 增量；101104 并发保护自动等待；门禁阈值阻断；DEFECT 详情 PDF；全缺陷+跟踪路径 JSON/HTML 归档；项目自动纳管v2 |
| `sca-scan.sh deps` | 组件依赖扫描 | 项目自动建/复用（v2带归属+成员）；红线卡点；任务统计（组件/漏洞四色）；SBOM+VEX 自动导出；结果 JSON 落盘 |
| `sca-scan.sh artifact` | 制品/固件成分扫描 | `SCAN_DIR`+`SCAN_PATTERNS` 控制范围，嵌入式场景用 |
| `sca-scan.sh report` | 报告生成+下载 | Excel 中文报告（需 `SCA_APP_ID`，deps 模式自动获取） |
| `sca-sbom.sh` | SBOM/VEX 单独导出 | SPDX 2.3 / CycloneDX 1.6 / CSAF 2.0 VEX，OpenAPI 直连生成+校验 |
| `sec-notify.sh` | 流水线末步执行 | 聚合卡片推送（钉钉加签/企微/飞书），TOP高危缺陷+统计+链接 |
| `codeai-scan.sh` | 全量扫描兜底 | 与增量脚本同一套 OpenAPI，无增量逻辑 |

## 快速开始（现场冒烟）

```bash
cp config.env.example config.env && vi config.env   # 填平台地址/令牌/归属人用户名/钉钉
source config.env
cd <某试点仓库>
bash <kit路径>/bin/sca-scan.sh provision            # 建或复用 SCA 项目(v2自动纳管)，落盘 provision.env
source ./provision.env
bash <kit路径>/bin/sca-scan.sh deps                 # 依赖扫描 + 自动 SBOM(SPDX)+VEX 导出
bash <kit路径>/bin/codeai-incremental-scan.sh       # CodeAI 首次全量 + 详情报告 + 全缺陷归档
bash <kit路径>/bin/sec-notify.sh                    # 推一张聚合卡片到钉钉
# 连续改一行代码再执行 → 日志出现"存在变更文件 → 增量扫描"即增量链路打通
```

云效 Flow 接入：仓库根放入 `sec-kit/`，流水线"自定义 Shell"步骤执行
`bash sec-kit/ci/yunxiao/yunxiao-security-step.sh`，界面配置见 `ci/yunxiao/云效Flow接入指南.md`。

## 换客户复用三步法

1. 复制整个 `govee-sec-kit/` 目录；
2. 改 `config.env.example`（▲必填 6 项：两平台地址/令牌 + 令牌归属人用户名 + 钉钉 webhook；其余默认即安全）；
3. 按客户 CI 平台取 `ci/` 下对应薄封装，新平台照抄一层"变量翻译"即可——封装里没有任何客户差异。

密钥注入优先级：CI 变量（推荐，Masked）> `source config.env`。令牌永不进仓库、永不进脚本。

## 安全边界说明

- `sca-scan.sh` 的 `BUILD_CMD` 是**流水线负责人专用的构建命令扩展钩子**（脚本头注释），只从环境变量读取，禁止从不可信输入（PR 内容、API 响应等）派生——与 CI 的 shell 步骤同信任级。
- 令牌类变量（SAST_TOKEN/SCA_USER_TOKEN/NOTIFY_WEBHOOK/NOTIFY_SECRET 等）一律走 CI Variables（Masked）或 config.env（.gitignore），本包所有文件均不含客户凭据。
- 扫描脚本为只读分析：上传源码包到客户自有平台，不执行仓库内容、不回写代码。
- 已知行为差异（v2 口径）：① SAST 项目成员仅创建时生效（平台 OpenAPI 无成员更新接口，后续加人走平台 UI）；② SCA 成员可随 `SCA_PROJECT_SYNC_MEMBERS=1` 幂等同步；③ VEX-CSAF 内容随平台侧漏洞审计推进而丰富（未审计=空清单，属 VEX 标准语义）；④ VEX-CycloneDX 在 SCA 4.13.0 上生成卡死，默认不导出。

## v2 实测记录（2026-10-12 · sast.igovee.com CodeAI 5.0 / sca.igovee.com SCA 4.13.0）

- SAST：项目自动创建（PM=令牌归属人/部门=归属人部门/成员=协作人userIds）✓；应用复用+增量扫描（基线 hash diff）✓；DEFECT 详情 PDF（13页全缺陷条目）✓；全缺陷导出（12条+全跟踪链，来源→跟踪→爆发点）✓
- SCA：项目 v2 创建（managerList/departmentId/memberList）✓；依赖扫描 21s；任务统计（16组件/60漏洞四色）✓；SPDX 2.3（16组件）+ CSAF 2.0 VEX 导出归档 ✓；Excel 报告 ✓
- GitHub Actions：真实云端 runner 三 job 全绿（SAST 并行 SCA、聚合归档、协作人自动拉取）✓；踩坑修复：GitHub 表达式未配置 `vars.X != '0'` 为 false（宽松相等 `''=='0'`）
- 云效：环境模拟全链路（CI_COMMIT_REF_NAME/CI_COMMIT_ID 翻译→双平台→产物/通知）✓
- 钉钉：真实机器人加签推送 ✓（聚合卡片）
