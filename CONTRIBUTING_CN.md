# 贡献指南

感谢你对 Verdict 的兴趣！

## 快速开始

### 前置要求

- Rust 1.75+（通过 [rustup](https://rustup.rs/) 安装）
- Cargo

### 项目设置

```bash
# 克隆仓库
git clone https://github.com/wwh-dghh/verdict.git
cd verdict

# 构建
cargo build

# 运行测试
cargo test

# 运行 CLI
cargo run -- check ./你的项目
```

## 项目结构

```
verdict/
├── src/
│   ├── main.rs          # CLI 入口（clap）
│   ├── models.rs         # 核心数据类型
│   ├── pipeline.rs       # 管道编排
│   ├── lint.rs           # Linter 适配器（Ruff、Biome、Oxlint）
│   ├── security.rs       # 安全规则扫描
│   ├── semantic.rs       # LLM-as-Judge 语义审查
│   ├── report.rs         # 终端/JSON/SARIF 报告
│   └── config.rs         # 配置加载器
├── testdata/             # 测试用例
├── Cargo.toml
└── README.md
```

## 如何贡献

### 1. 报告 Bug

使用 [GitHub Issues](https://github.com/wwh-dghh/verdict/issues) 报告 bug，请包含：
- 复现步骤
- 预期行为 vs 实际行为
- 你的操作系统和 Verdict 版本

### 2. 功能建议

我们欢迎功能建议！请描述：
- 你想解决的问题
- Verdict 如何解决
- 你考虑过的替代方案

### 3. 提交代码

1. Fork 本仓库
2. 创建功能分支（`git checkout -b feature/新功能`）
3. 编写代码
4. 运行 `cargo fmt` 和 `cargo clippy`
5. 添加单元测试
6. 提交并推送，创建 Pull Request

### 4. 添加新的安全规则

参见 `src/security.rs` — 每条规则是一个 `SecurityPattern`：

```rust
SecurityPattern::new(
    r"正则表达式模式",       // 匹配规则的正则
    Severity::Error,         // 严重等级
    "SEC008",               // 规则编号
    "规则描述",              // 简短描述
    Some("修复建议"),         // 可选的修复建议
)
```

### 5. 添加新的 Linter

参见 `src/lint.rs` — 实现 `LintAdapter` trait：

```rust
struct MyLinterAdapter;

#[async_trait::async_trait]
impl LintAdapter for MyLinterAdapter {
    fn name(&self) -> &str { "my-linter" }
    async fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        // 作为子进程运行 linter
        // 解析输出为 Finding 结构体
    }
}
```

## 编码规范

- 运行 `cargo fmt` 格式化代码
- 运行 `cargo clippy -- -D warnings` 确保无警告
- 函数保持小而专注
- 为不明显的逻辑添加注释
- 为新功能编写测试

## 发布流程

1. 更新 `Cargo.toml` 中的版本号
2. 更新 `CHANGELOG.md`
3. 打标签：`git tag v0.x.x`
4. 推送：`git push && git push --tags`
5. 发布到 crates.io：`cargo publish`

## 许可证

贡献代码即表示你同意你的贡献采用 MIT 许可证。
