# ssoAPI

提供通过账号密码获得ECNU统一认证CAS票据的流程。

依赖Playwright实现，启动浏览器前建议调用`EnsureEnvironment()`检查并配置环境。

调用`GetTicketWithAccount()`通过账号密码取票，同时返回`SOURCEID_TGC`，用于在有效期内免密取票。

调用`GetTicketWithSourceId()`通过`SOURCEID_TGC`取票，若过期则调用`GetTicketWithAccount()`刷新。