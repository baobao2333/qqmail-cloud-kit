# 快速开始：官方 CLI 直接登录

推荐在普通公网 Linux 服务器或同网络电脑运行。需要能访问 QQ 邮箱官方 OAuth/MCP 和 npm；授权页面由用户亲自确认。先解压已核验的发布 ZIP，进入源码目录。以下命令都在你的终端执行。

## 1. 建立新专用目录

选一个尚不存在、父目录已存在的路径。示例不会覆盖原来的 `~/.codex`。

```sh
export QQMAIL_CODEX_HOME="$HOME/.codex-qqmail"
python3 prepare_home.py --home "$QQMAIL_CODEX_HOME"
export CODEX_HOME="$QQMAIL_CODEX_HOME"
umask 077
```

初始化器生成 `config.toml`、私有 `requests/` 和空 `mail-runtime/`；已有目录会退出非零。要复用此前专用目录时，检查其配置和权限后直接设置环境变量，不再次初始化。目录和配置分别为 `0700`、`0600`。

## 2. 在专用目录安装固定 CLI

```sh
npm install --prefix "$QQMAIL_CODEX_HOME/cli" @openai/codex@0.159.2
export CODEX_BIN="$QQMAIL_CODEX_HOME/cli/node_modules/.bin/codex"
"$CODEX_BIN" --version
```

应显示 `codex-cli 0.159.2`。这只安装专用副本，不替换已工作的全局 CLI。Python 辅助程序读取 `CODEX_BIN`，官方 CLI 读取 `CODEX_HOME`。

## 3. 直接执行官方 OAuth

```sh
"$CODEX_BIN" mcp login qqmail \
  --scopes alias:read,mail:read \
  --oauth-client-registration dcr
```

明确传入只读 scope，避免采用服务发现中可能包含的额外权限。官方客户端执行 DCR、PKCE 和凭据存储。检查当前 URL 的官方域名 `wx.mail.qq.com` 及授权页面权限，再亲自确认；只使用本次进程给出的 URL。

浏览器与 CLI 在同一台电脑时，回调可直接访问其本地监听器。CLI 在远程服务器时，在浏览器电脑上另开 SSH 终端转发端口，再打开当前官方授权 URL：

```sh
ssh -N -L 14556:127.0.0.1:14556 your-server
```

`your-server` 是你已有 SSH 配置中的服务器别名，请按实际替换。回调地址里的 `127.0.0.1` 指浏览器所在电脑；端口转发把它交给服务器。不要将回调监听器暴露为公网接口。

如果直接回调或自动启动浏览器不适合当前环境，参见 [官方隐藏输入与私密表单](HEADLESS.md)。不要把回调粘贴到聊天，也不要通过命令行参数、临时文本文件或 `echo` 管道提交。

## 4. 只读检查和搜索

```sh
python3 check_qqmail.py status
python3 check_qqmail.py tools
python3 check_qqmail.py getme
python3 check_qqmail.py readcheck
```

`status` 列出连接状态，`tools` 列出当前服务 schema。`getme` 会读取账号资料，`readcheck` 再读取一封收件箱摘要；结果是个人数据，请只在私有终端查看。脚本没有发送、删除或任意工具调用入口。

通用参数必须放在专用目录的 `requests/` 中。按 `tools` 返回的最新 schema 写入 JSON，例如原型验证过的收件箱参数：

```sh
cat > "$QQMAIL_CODEX_HOME/requests/search.json" <<'JSON'
{"dir":"inbox","limit":1}
JSON
chmod 600 "$QQMAIL_CODEX_HOME/requests/search.json"
python3 check_qqmail.py search "$QQMAIL_CODEX_HOME/requests/search.json"
```

读取正文时，将搜索返回的 `message_id` 写入另一份私有 JSON：

```json
{"message_id":"REPLACE_WITH_SEARCH_RESULT_ID"}
```

```sh
python3 check_qqmail.py message "$QQMAIL_CODEX_HOME/requests/message.json"
```

不要使用示例占位 ID 发起请求。参数只支持服务公布的基础类型；未知字段、缺失必填字段和不支持的 schema 会失败。退出码 `0` 表示请求执行成功，非零表示失败；请同时检查服务结果中的业务错误。

## 5. 需要发送权限时显式选择

默认授权不含发送权限。只有确实需要时，重新授权并明确加上 `mail:send`：

```sh
"$CODEX_BIN" mcp login qqmail \
  --scopes alias:read,mail:read,mail:send \
  --oauth-client-registration dcr
```

新专用目录也可使用 `prepare_home.py --home NEW_PRIVATE_DIRECTORY --enable-send`。桥接工具对应 `--enable-send`。这些选项只扩展授权请求；本包的只读工具白名单继续生效，不提供发送操作。实际发送需要另行明确配置和审核客户端。不要加入删除权限。

凭据文件只检查权限，不查看内容；日志和备份策略见 [安全说明](../SECURITY.md)。撤销授权请使用 QQ 邮箱账户提供的授权管理功能，或对同一专用目录执行官方 `mcp logout qqmail`，需要重新连接时由用户再次授权。
