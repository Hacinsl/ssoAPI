package ssoapi

import (
	"fmt"
	"strings"
	"time"

	"github.com/mxschmitt/playwright-go"
)

// fetchTicketWithSourceId 用调用方已有的 SOURCEID_TGC 直接换票
func fetchTicketWithSourceId(opt *TicketOptions) *TicketResp {
	resp := &TicketResp{}

	tgc := normalizeSourceID(opt.SourceID)
	if tgc == "" {
		resp.Err = fmt.Errorf("Failed to fetch ticket: sourceId is empty.")
		return resp
	}

	session, err := newPwSession()
	if err != nil {
		resp.Err = fmt.Errorf("Failed to fetch ticket: %w", err)
		return resp
	}
	defer session.Close()
	page := session.page

	if err := session.ctx.AddCookies([]playwright.OptionalCookie{{
		Name:     "SOURCEID_TGC",
		Value:    tgc,
		Domain:   playwright.String("sso.ecnu.edu.cn"),
		Path:     playwright.String("/"),
		HttpOnly: playwright.Bool(true),
		Secure:   playwright.Bool(true),
	}}); err != nil {
		resp.Err = fmt.Errorf("Failed to set SOURCEID_TGC cookie: %w", err)
		return resp
	}

	ticketCh := watchTicket(page)

	loginURL, err := loginPageURL(opt.Service)
	if err != nil {
		resp.Err = fmt.Errorf("Failed to build login page url: %w", err)
		return resp
	}

	_, gotoErr := page.Goto(loginURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateCommit,
		Timeout:   playwright.Float(15000),
	})

	// ticket 出现在 302 的中间跳，早于 Goto 等待的 commit 事件：
	// 导航失败（service 慢、返回附件触发 ERR_ABORTED 等）并不代表没拿到票；
	// 反之 Goto 成功也不代表票已在 channel 里，两条路径都必须等。
	// page.OnRequest 的回调由 driver 连接的 dispatch goroutine 异步派发，
	// Goto 返回时 302 的 request 事件可能尚未投递，所以失败路径也要留 3s 宽限，不能零等待判死。
	ticketWait := 10 * time.Second
	if gotoErr != nil {
		ticketWait = 3 * time.Second
	}

	if ticket, ok := awaitTicket(ticketCh, ticketWait); ok {
		resp.Ticket = ticket
		resp.SourceID = tgc // 成功才回显 TGC，避免调用方持久化已失效的值
		return resp
	}

	if gotoErr != nil {
		resp.Err = fmt.Errorf("Failed to open login page: %w", gotoErr)
		return resp
	}

	// TGC 失效时 CAS 会回退渲染登录页，据此区分失败原因
	if _, err := waitAnyVisible(page, []string{`#nameInput`, `input[name="username"]`}, 2*time.Second); err == nil {
		resp.Err = fmt.Errorf("Failed to fetch ticket: SOURCEID_TGC has expired.")
	} else {
		resp.Err = fmt.Errorf("Failed to fetch ticket: timed out.")
	}
	return resp
}

// awaitTicket 在 d 内等待 ticket 出现。
func awaitTicket(ch <-chan string, d time.Duration) (string, bool) {
	select {
	case ticket := <-ch:
		return ticket, true
	case <-time.After(d):
		return "", false
	}
}

// normalizeSourceID 抽出裸 TGC，容忍纯 JWT、带引号、"SOURCEID_TGC=xxx"、
// 完整 Set-Cookie（"SOURCEID_TGC=xxx; Path=/; HttpOnly"）以及整条 Cookie 头。
func normalizeSourceID(raw string) string {
	for _, part := range strings.Split(raw, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.Trim(strings.TrimSpace(name), "\"'")
		if !strings.EqualFold(name, "SOURCEID_TGC") {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), "\"'")
	}

	// 不含 "NAME=VALUE" 形式时按裸值处理（纯 JWT 或带引号的裸值）。
	return strings.Trim(strings.TrimSpace(raw), "\"'")
}
