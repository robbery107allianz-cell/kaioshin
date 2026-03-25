# Kaioshin v2 — 开发规范

## 项目定位
Mac 本地安全审计工具。扫描浏览器扩展、敏感文件、加密钱包、网络连接、AI 工具安全。
**只读审计，不做防护。** 界王神不出手，只看穿一切。

## 架构

```
kai (CLI 入口) → cli.py (命令解析) → scanner/*.py (扫描模块) → reporter/*.py (输出)
```

### 扫描模块
| 模块 | 文件 | 职责 |
|------|------|------|
| 浏览器扩展 | scanner/extensions.py | 解析 manifest.json，权限评估，风险评级 |
| 敏感文件 | scanner/secrets.py | SSH/AWS/GPG/Keychain 暴露面检测 |
| 加密钱包 | scanner/wallets.py | 钱包扩展、IndexedDB DApp 痕迹、桌面钱包 |
| 网络连接 | scanner/network.py | lsof 出站连接、可疑端口/目标检测 |
| AI 工具 | scanner/ai_agents.py | AI 编程工具安全评级 |

### 输出模块
| 模块 | 文件 | 职责 |
|------|------|------|
| 终端 | reporter/terminal.py | 彩色终端输出 |
| 报告 | reporter/markdown.py | Markdown 审计报告，输出到 reports/ |

### 知识库
| 文件 | 内容 |
|------|------|
| knowledge/malicious_extensions.yaml | 已知恶意扩展 ID 和特征 |
| knowledge/risk_matrix.yaml | 风险分级标准 P0/P1/P2 |

## 开发规则

1. **只读** — 绝不修改、删除被扫描的文件
2. **不输出敏感内容** — 报告只显示路径和元数据，绝不显示文件内容
3. **零必需依赖** — 标准库为主，PyYAML 可选
4. **每个 scanner 模块必须有 `scan_all()` 函数** — 返回 dataclass 列表
5. **新增扫描器步骤**：
   - 在 scanner/ 下新建模块
   - 定义返回的 dataclass
   - 实现 scan_all()
   - 在 reporter/terminal.py 加 print 函数
   - 在 reporter/markdown.py 加报告章节
   - 在 cli.py 注册命令

## Git 工作流
- v2 分支开发，完成后合并 main
- commit message: `feat:` / `fix:` / `docs:` / `refactor:`

## 风险分级
- **P0 Catastrophic** — 不可逆财务损失或身份泄露
- **P1 Severe** — 重大数据暴露或凭证泄漏
- **P2 Medium** — 有限暴露，纵深防御层面
