# ssoAPI

提供ECNU统一认证的客户端实现，兼容CAS登录与Oauth授权。

## 用法

- `GetTicketWithAccount()` 通过账号密码完成 CAS 认证。若给定`CasOptions.Service`，则返回`CasResp.SourceID`与对应服务的`CasResp.Ticket`，否则返回`CasResp.SourceID`与 sso-self 的`CasResp.Ticket`。
- `GetTicketWithTgc()` 通过有效`CasOptions.SourceID`完成 CAS 认证。返回对应服务的`CasResp.Ticket`。
- `GetPasskeyWithTgc()` 通过有效`CasOptions.SourceID`完成 Passkey 注册。返回`CasResp.Passkey`。
- `GetTgcWithPasskey()` 通过有效`CasOptions.Passkey`完成 CAS 认证。返回`CasResp.SourceID`。
- `GetCodeWithTgc()` 通过有效`CasOptions.SourceID`完成 Oauth 认证。返回对应应用的`OauthResp.Code`、`OauthResp.State`与`OauthResp.Session`。

需要注意，无论是`CasResp`还是`OauthResp`都仅对该轮次注释中明确写出的字段负责，请勿直接用返回值覆盖状态。特别地，由于使用 Passkey 登录的场景需要更新使用计数，因此必须在`CasResp.Passkey`不为空时将其覆盖到状态并持久化。

账密登录依赖 Playwright 绕过风控，启动浏览器前建议调用`EnsureEnvironment()`检查并配置环境。实际在云端部署时，建议在本地取得 Passkey 后同步至服务器，避免在云端重复构建 Playwright 环境。

## 回落

`ssoAPI`提供从 CAS TGC 到 Passkey/Account 的回落，用于在上级凭据过期时自动通过下级凭据刷新，防止业务中断。

在判定 CAS TGC 可能过期时，将优先尝试使用 Passkey 刷新，若未提供则使用 Account。若均未提供则返回错误。由于 Account 途径依赖 Playwright，请尽量在条件允许时传入 Passkey。

回落触发时，返回的`CasResp`会包含新的 CAS TGC，旧值即时失效。