package ssoapi

import (
	"errors"
	"os"
)

var (
	noSandbox                 bool = false        // Playwright 选项，在 Linux 设备上以 root 权限运行时需设置为 true。
	EnablePasskeyAutoAddCount bool = true         // 启用密钥自动提升使用计数，防止密钥共用引起的次数不同步。
	EnableLog                 bool = false        // 启用日志输出。
	LogLevel                  int  = LogLevelInfo // 日志等级，仅输出不高于该等级的日志。
)

// 通过 Playwright 启动真实浏览器进行认证，以绕过登录页风控。
// 使用 CasOption 中的 Account/Password，返回有效 SourceID/Ticket。
func GetTicketWithAccount(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to fetch ticket: options is nil.")
	}
	applyHTTPDebug()
	return casWithAccount(opt)
}

// 使用 CasOption 中的 SourceID，若触发回落则使用 Account/Password/Passkey。返回匿名 Session，有效 Ticket/Location。无法取得 Ticket 时报错。
func GetTicketWithTgc(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to fetch ticket: options is nil.")
	}
	applyHTTPDebug()
	return casWithTgcForService(opt)
}

// 使用 CasOption 中的 SourceID，若触发回落则使用 Account/Password。返回注册得到的 Passkey。
func GetPasskeyWithTgc(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to register passkey: options is nil.")
	}
	applyHTTPDebug()
	return registerPasskey(opt)
}

// 使用 CasOption 中的 SourceID，若触发回落则使用 Account/Password/Passkey。返回有效Oauth Code。
func GetCodeWithTgc(opt *OauthOptions) (*OauthResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to get code: options is nil.")
	}
	applyHTTPDebug()
	return oauthWithTgc(opt)
}

// 使用 CasOption 中的 Passkey，返回有效 SourceID。若 Passkey 使用计次需要提升则返回更新后的 Passkey。
func GetTgcWithPasskey(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to fetch tgc: options is nil.")
	}
	applyHTTPDebug()
	return loginPasskey(opt)
}

func init() {
	if os.Getuid() == 0 {
		noSandbox = true
	}
}
