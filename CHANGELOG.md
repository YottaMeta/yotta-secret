# Changelog

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
