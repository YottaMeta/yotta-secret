# Changelog

## v0.1.2 (2026-08-29)

- 安装方式统一为四方式（对齐发布规范 §3.3.1）：方式一 `npx -y @yottameta/yotta-secret --agent <name>` / `--dir <dir>`（推荐，走 npm 源）；方式二 `git clone https://github.com/YottaMeta/yotta-secret.git`；方式三 GitHub Download ZIP；方式四 `bash install.sh --agent/--dir/--list`。移除 `npx skills` 与 `-g` 推荐；中英双 README 安装节同步。
- 版本对齐：package.json / SKILL.md / CHANGELOG / 引擎 VERSION / 测试断言 / README 锚点 = 0.1.2。
- 维护修复（续14）：generic 规则新增 URL 区间跳过（_inside_url），修复 URL 路径内高熵段误报（shields.io badge / git clone）；3 条回归测试，94/94 全绿。
- 无功能变更（仅文档与版本同步）。

## 0.1.1 (2026-08-28)

README 安装说明修复 + 围栏修复（三源同步重发）：

- **README.md / README.zh-CN.md 安装节重构**：移除 `npx -y @yottameta/yotta-secret --agent codex` 固定智能体安装行（违反安装规范：npx 用 -g 或 --dir，--agent 仅 install.sh 用），改为标准三方式（npm 一行 / install.sh / 手动复制 + 17 类智能体目录表）。
- **代码围栏修复**：中文 README 中单反引号伪围栏（`bash … `）改为标准三反引号 ```bash … ```（Markdown 渲染修复，线上 0.1.0 为坏版本）。
- 版本对齐：package.json / SKILL frontmatter / 引擎 VERSION / 测试断言 / CHANGELOG = 0.1.1。
- 无功能 / 引擎变更。

## 0.1.0 (2026-08-27)

- 初始版本：零依赖密钥 / 凭据泄露源头扫描引擎（Python 3.8+ 标准库）。
- 五类检测：cloud（AWS / Google / OpenAI / GitHub / Slack / Stripe / JWT 等 20+ 云厂商与 SaaS 规则）、
  private_key（PEM / PGP / OpenSSH / PuTTY 私钥块）、credential（口令赋值，含后缀式 key）、
  url_userinfo（URL 内嵌账号密码）、generic（高熵长 token）。
- 三重判定：正则格式 → Shannon 熵阈值 → 值级校验（纯哈希 / UUID / 占位符 / 示例值过滤）。
- 子命令：scan（文件 / 目录 / stdin / git 历史）、verify（单值判定）、mask（脱敏，与元史同源）、
  entropy（信息熵）。
- 输出：text / JSON / CSV；默认打码（--show-secret 才明文）。
- 测试：91/91 全绿。
