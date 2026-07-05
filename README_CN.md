# Verdict

**AI 代码，人类信心。**

一个通过静态分析、安全扫描和 AI 驱动的语义审查来验证 AI 生成代码质量的 CLI 工具。

## 为什么需要 Verdict？

AI 编程助手在生成代码方面表现出色——但你如何确定它生成的代码是**安全的**、**正确的**、**高质量的**？Verdict 填补了"能跑"和"生产可用"之间的鸿沟。

## 功能特性

- **静态分析** — 集成 Ruff（Python）、Biome/Oxlint（JS/TS）进行代码质量检查
- **安全扫描** — 检测 SQL 注入、XSS、硬编码密钥、弱加密等漏洞
- **AI 语义审查** — 可选的 LLM-as-Judge 模块，进行更深层的代码质量分析
- **多维评分** — 安全性、代码质量、性能、测试覆盖、AI 风险
- **三种输出格式** — 终端（彩色）、JSON、SARIF（CI/CD 兼容）
- **CI/CD 门禁** — 可配置的质量阈值，自动通过/失败构建
- **增量分析** — Git diff 感知模式，只分析变更的文件
- **可扩展插件** — 社区自定义规则插件系统

## 安装

### 从 crates.io 安装

```bash
cargo install verdict
```

### 从源码编译

```bash
git clone https://github.com/wwh-dghh/verdict.git
cd verdict
cargo build --release
```

## 快速开始

```bash
# 分析目录
verdict check ./src

# 开启 AI 语义审查（需要配置 LLM API key）
verdict check ./src --explain

# JSON 格式输出（CI/CD 集成）
verdict check ./src -f json

# 查看安全规则清单
verdict rules

# 生成配置文件模板
verdict init > .verdict.yaml
```

## 配置

在项目根目录创建 `.verdict.yaml` 文件：

```yaml
# 要分析的目标目录
targets: ["./src"]

# 要检查的语言（留空则自动检测）
languages: [python, javascript, typescript]

# 启用安全扫描
security_scan: true

# 启用 AI 语义审查（需要配置 LLM）
ai_review: false

# 输出格式：terminal, json, sarif
output: terminal

# 忽略的文件/目录
ignore:
  - ".git"
  - "node_modules"
  - "__pycache__"
  - "target"
  - "venv"

# CI/CD 质量阈值（0-100）
thresholds:
  security: 70
  code_quality: 60
  overall: 50
```

## 架构

```
CLI (clap)
  │
  ▼
Pipeline 编排器
  ├── 预处理    → 文件发现 & 语言检测
  ├── 代码审查   → Ruff / Biome / Oxlint 适配器
  ├── 安全扫描   → 基于规则的漏洞检测
  ├── 语义审查   → LLM-as-Judge（可选）
  ├── 评分聚合   → 多维度加权评分
  └── 报告生成   → 终端 / JSON / SARIF
```

## 安全规则

| 规则码 | 描述 | 严重度 |
|--------|------|--------|
| SEC001 | 潜在 SQL 注入 | 错误 |
| SEC002 | 潜在 XSS 攻击 | 错误/警告 |
| SEC003 | 硬编码密钥/密码 | 错误 |
| SEC004 | 弱加密算法（MD5、DES） | 警告 |
| SEC005 | 调试日志泄露敏感信息 | 警告 |
| SEC006 | 危险的 eval() 使用 | 错误 |
| SEC007 | 命令注入 | 错误 |

## 演示

```
$ verdict check ./src

════════════════════════════════════════════════════════════
  Verdict — AI Code Verification Report
════════════════════════════════════════════════════════════

  Files analyzed: 3
  Total findings: 5
  ✗ 2 error(s)
  ⚠ 3 warning(s)

  📊 Scores for src/auth.py: 62/100 (security:50!)
  📊 Scores for src/api.js: 85/100
  📊 Scores for src/utils.rs: 95/100

  ──────────────────────────────────────────────────
  src/auth.py:
  src/auth.py [ERROR]  SEC003 Possible hardcoded secret detected
    → Use environment variables or a secrets manager
  src/auth.py [WARN]  SEC004 Weak hash function (MD5) detected
    → Use SHA-256 or bcrypt for password hashing
```

## 路线图

- [x] 核心管道架构
- [x] 安全扫描（7 条内置规则）
- [x] 终端、JSON、SARIF 输出
- [x] LLM-as-Judge 语义审查
- [x] `verdict init` / `verdict rules` 命令
- [ ] Git diff 增量分析
- [ ] WASM 插件系统
- [ ] pre-commit 钩子集成
- [ ] IDE 扩展（VS Code）
- [ ] 更多语言支持（Go、Rust）

## 贡献指南

欢迎贡献！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细指南。

## 许可证

[MIT License](LICENSE)
