# MASS 安全分类方法论

> Version: 1.0
> Date: 2026-03-03

---

## 分类原则

### 一、按"损失不可逆性"分级

| 级别 | 定义 | 示例 | 应对 |
|------|------|------|------|
| P0 - 致命 | 丢失后无法恢复，直接经济损失 | 钱包助记词、交易所密码 | 绝对封锁，零容忍 |
| P0 - 致命 | 可登录所有在线账户 | 浏览器密码、Cookies、Keychain | 绝对封锁 |
| P1 - 严重 | 可恢复但代价高 | SSH 私钥、GPG 密钥 | 强封锁，白名单例外 |
| P1 - 严重 | 涉及隐私或社交关系 | 聊天记录、通讯录 | 强封锁 |
| P2 - 中等 | 可重新生成但有工作中断 | API tokens、dev credentials | 默认封锁，可按需开放 |
| P3 - 低 | 公开或半公开信息 | 公钥、配置文件、代码 | 开放 |

### 二、按"数据归属"分类

| 归属 | 说明 | 策略 |
|------|------|------|
| 系统级 | macOS Keychain、auth.db、Secure Enclave | 全锁，无例外 |
| 应用级 | Chrome、Firefox、Telegram 等 APP 私有数据 | 按 APP 锁定整个数据目录 |
| 用户级 | .ssh、.gnupg、.env 等用户自建凭证 | 按目录/文件锁定 |
| 工作级 | 项目代码、笔记、文档 | 开放（AI 工作区） |

### 三、按"访问方式"防御

AI agent 访问敏感数据有三种方式，每种都需要单独防御：

| 方式 | 说明 | 防御手段 |
|------|------|----------|
| 文件读取 | Read/cat/head 等直接读文件 | sandbox-exec deny file-read* |
| 命令执行 | security dump-keychain, sqlite3 打开 DB | sandbox-exec deny process-exec + Hook |
| 路径搜索 | Glob/Grep/find 发现敏感文件 | sandbox-exec deny file-read-metadata |

---

## 沙箱规则生成逻辑

```
categories.yaml → 解析路径列表 → 生成 sandbox.sb → 包裹 AI 进程
```

### sandbox.sb 规则优先级

1. `(allow default)` — 默认允许所有操作
2. `(deny file-read* (subpath "..."))` — 按类别禁止读取
3. `(deny file-write* (subpath "..."))` — 按类别禁止写入
4. `(deny process-exec (literal "..."))` — 禁止执行特定命令
5. `(allow file-read* (subpath "..."))` — 白名单: AI 工作目录

### 为什么是 "默认允许 + 黑名单禁止"？

因为 AI agent 需要广泛的系统访问权限才能正常工作（读写项目文件、执行编译命令、访问网络等）。
采用"默认禁止 + 白名单允许"会导致 agent 功能严重受限，难以实用。
所以我们选择"默认允许 + 精确封锁敏感区域"，最小化对 AI 工作能力的影响。

---

## 与现有安全机制的关系

| 机制 | 层级 | MASS 的关系 |
|------|------|-------------|
| macOS SIP | 内核级 | 不冲突，SIP 保护系统文件，MASS 保护用户数据 |
| macOS TCC | 应用级 | 互补，TCC 管摄像头/麦克风/通讯录，MASS 管文件路径 |
| FileVault | 磁盘级 | 不冲突，FileVault 防物理窃取，MASS 防 AI 误读 |
| Gatekeeper | 应用级 | 不冲突，Gatekeeper 防恶意 APP 安装 |
| sandbox-exec | 进程级 | MASS 的核心引擎 |
| PreToolUse Hook | AI 工具级 | MASS 的应用层防御 |

---

## 可扩展性设计

### 新增 APP 的流程

1. 确认 APP 的本地数据目录
2. 归入已有类别（browsers / messaging / dev-secrets / custom）
3. 将路径添加到 categories.yaml 对应类别
4. 重新生成 sandbox.sb
5. 重启 AI agent

### 新增 AI agent 的流程

1. 确认 agent 的启动命令
2. 在 ai-sandbox.sh 中添加一行 launch 配置
3. 使用 `./mass launch <agent-name>` 启动
4. 安全规则自动适用，无需修改

### 迁移到新 Mac 的流程

1. `git clone` MASS 仓库
2. 运行 `./mass scan` 扫描新机器
3. 人工确认扫描结果
4. 运行 `./mass generate` 生成配置
5. 完成

---

*MASS Methodology v1.0 — 小code*
