package ssoapi

import (
	"errors"
	"os"
)

var noSandbox bool = false
var EnableDebugOutput bool = false

// GetTicketWithAccount 通过账号密码取票，同时返回 SOURCEID_TGC。
func GetTicketWithAccount(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to fetch ticket: options is nil.")
	}
	return casWithAccount(opt)
}

// GetTicketWithTgc 强制使用 SOURCEID_TGC 换票，不提交账号密码。
func GetTicketWithTgc(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to fetch ticket: options is nil.")
	}
	return casWithTgcForService(opt)
}

// GetPasskeyWithTgc 用已有的 SOURCEID_TGC 免密登录并注册 passkey。
func GetPasskeyWithTgc(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to register passkey: options is nil.")
	}
	return registerPasskey(opt)
}

func GetCodeWithTgc(opt *OauthOptions) (*OauthResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to get code: options is nil.")
	}
	return oauthWithTgc(opt)
}

func GetTgcWithPasskey(opt *CasOptions) (*CasResp, error) {
	if opt == nil {
		return nil, errors.New("Failed to fetch tgc: options is nil.")
	}
	return loginPasskey(opt)
}

func init() {
	if os.Getuid() == 0 {
		noSandbox = true
	}
}

// 把用TGC取票的环节不依赖playwright
// oauth相关接口对外
