# QQ 邮箱云端接入工具包

v0.1.0 原型：使用官方 QQ 邮箱 MCP `https://api.mail.qq.com/mcp`，通过官方 Codex CLI 完成用户亲自授权，再用只读工具检查连接、搜索邮件和读取正文。OAuth 和凭据刷新由官方客户端处理，本包不实现另一套账号登录。

默认只请求 `alias:read`、`mail:read`，并只允许 `GetMe`、`SearchMessages`、`GetMessage`。`mail:send` 需要显式选项；本包没有发送或删除命令，不提供 `mail:delete`。

## 从这里开始

使用 Linux/POSIX、Python 3.11+、Node/npm 和 **Codex CLI 0.159.2**。下载 Release 源码 ZIP、核对随附 SHA256 后解压，按照 [快速开始](docs/QUICKSTART.md) 操作。Python 脚本只使用标准库，不需要 pip 安装依赖。

普通网络环境优先直接执行官方 CLI 登录。浏览器在另一台电脑时，先用 SSH 转发本地回调端口；没有可用浏览器启动器时，可使用官方隐藏输入。FIFO 与私密回调表单只用于需要桥接的情况，详见 [可选无浏览器方案](docs/HEADLESS.md)。

本包创建新的专用 `CODEX_HOME`，拒绝覆盖已有目录。不会修改已有 Codex 连接或操作系统隔离设置。

## 安全与验证范围

示例选择 `file` 凭据后端。**OAuth 凭据会由官方 CLI 写入明文文件**；Linux/POSIX 目录应为 `0700`、凭据文件应为 `0600`，这些权限不是加密。授权可过期或撤销，无法保证永久免登录。详见 [安全说明](SECURITY.md)。

原型在 Linux 云端、Codex 0.159.2 完成了真实 OAuth、`GetMe`、`SearchMessages`、`GetMessage` 和新进程凭据复用验证。此发布版的工程化修改使用合成数据离线测试；不把原型实测冒充为本版再次在线测试。辅助脚本调用实验 app-server RPC，版本兼容性和平台限制见 [已知限制与验证记录](docs/LIMITATIONS.md)。

邮件输出依然可能包含姓名、地址和正文。过滤器仅遮蔽已知凭据字段及敏感链接，不是任意隐私信息分类器。不要把输出、授权 URL、回调 URL 或凭据上传到 GitHub。

## 开发与打包

```sh
python3 -B -m unittest discover -s tests -v
python3 -B scripts/build_release.py
```

Windows 可以运行纯逻辑离线测试和打包。FIFO、文件权限和管道运行测试会明确跳过；本包的登录桥接、初始化与 app-server 辅助程序不支持 Windows 原生运行。CI 在 Linux 和 Windows 运行同一套离线测试，不连接邮箱。

发布包使用明确文件白名单，包含源码、测试、部署文档和版本号，不包含运行目录、凭据或邮件。未指定开源许可证；公开可见不等于授予任意复用或再分发许可，许可证待维护者指定。

官方参考：[Codex MCP 文档](https://developers.openai.com/codex/mcp)、[0.159.2 登录实现](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/cli/src/mcp_login.rs)、[0.159.2 回调校验实现](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/rmcp-client/src/oauth_callback_input.rs)。
