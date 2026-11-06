package ssoapi

import (
	"errors"
	"os"
)

// TicketOptions 是一次取票请求的参数。
type TicketOptions struct {
	// Service 是 CAS 的 service 参数，登录成功后 CAS 会带着 ticket 跳回该地址。
	Service string
	// Account 是学工号 / 账号；用 SourceID 换票时可以留空。
	Account string
	// Password 是密码；用 SourceID 换票时可以留空。
	Password string
	// SourceID 是已有的 SOURCEID_TGC，非空时表示免密码换票。
	SourceID string
}

// TicketResp 是一次取票的结果。
type TicketResp struct {
	// Ticket 是 CAS 重定向地址上的 ticket 参数，一次性有效。
	Ticket string
	// SourceID 是本次登录拿到的 SOURCEID_TGC，可作为长期凭据复用（免密码换票）。
	SourceID string
	// Err 是失败原因。
	Err error
}

var noSandbox bool

// GetTicket 通过账号密码取票，同时返回 SOURCEID_TGC。
func GetTicketWithAccount(opt *TicketOptions) *TicketResp {
	if opt == nil {
		return &TicketResp{Err: errors.New("Failed to fetch ticket: options is nil.")}
	}
	return fetchTicket(opt)
}

// GetTicketWithSourceId 强制使用 SOURCEID_TGC 换票，不提交账号密码。
func GetTicketWithSourceId(opt *TicketOptions) *TicketResp {
	if opt == nil {
		return &TicketResp{Err: errors.New("Failed to fetch ticket: options is nil.")}
	}
	return fetchTicketWithSourceId(opt)
}

func init() {
	if os.Getuid() == 0 {
		noSandbox = true
	}
}
