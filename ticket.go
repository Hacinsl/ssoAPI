package ssoapi

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mxschmitt/playwright-go"
)

func fetchTicket(opt *TicketOptions) *TicketResp {
	resp := &TicketResp{}

	session, err := newPwSession()
	if err != nil {
		resp.Err = fmt.Errorf("Failed to fetch ticket: %s", err)
		return resp
	}
	defer session.Close()
	page := session.page

	// 两个 channel 的发送端都跑在 playwright 的 dispatch goroutine 上，一旦阻塞就会连命令回复都无法投递，因此一律用非阻塞发送。
	ticketCh := watchTicket(page)
	respCh := watchSourceId(page)

	stop := make(chan struct{})
	var once sync.Once
	closeDropResp := func() {
		once.Do(func() { close(stop) }) // defer与手动关闭同时存在，这里保证仅关闭一次。
	}
	defer closeDropResp()
	go dropResps(respCh, stop) // 在提交登录表单前丢弃response防止cookie丢失。

	loginURL, err := loginPageURL(opt.Service)
	if err != nil {
		resp.Err = fmt.Errorf("Failed to build login page url: %s", err)
		return resp
	}

	if _, err := page.Goto(loginURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(10000),
	}); err != nil {
		resp.Err = fmt.Errorf("Failed to open login page: %s", err)
		return resp
	}

	if err := fillLoginForm(page, opt); err != nil {
		resp.Err = fmt.Errorf("Failed to autofill: %s", err)
		return resp
	}

	// 停止丢弃cookie收集
	closeDropResp()

	if err := submitLogin(page); err != nil {
		resp.Err = fmt.Errorf("Failed to submit login: %s", err)
		return resp
	}

	timeout := 15 * time.Second
	deadlineCh := time.After(timeout)

	var haveTicket, haveSourceID bool

waitLoop:
	for {
		select {
		case respWithCookie := <-respCh:
			if sourceId, ok := sourceIDTGC(respWithCookie); ok {
				resp.SourceID = sourceId
				haveSourceID = true
			}
		case resp.Ticket = <-ticketCh:
			haveTicket = true
		case <-deadlineCh:
			resp.Err = fmt.Errorf("Timed out.")
			break waitLoop
		}

		// ticket与cookie都收集到
		if haveTicket && haveSourceID {
			break waitLoop
		}
	}

	return resp
}

// allowedHosts 是登录流程必须放行的主机名，逐字精确匹配，不做任何子域推导：
var allowedHosts = []string{
	"sso.ecnu.edu.cn",    // CAS 登录页、POST /login 与带 ticket 的 302
	"c.dun.163.com",      // 易盾验证码脚本与 check 接口
	"dun.163.com",        // 易盾主域
	"cstaticdun.126.net", // 易盾验证码静态资源
	"localhost",          // 本地回环（调试/驱动），避免误伤
}

// hostResolverRules 把 Chromium 的 DNS 收成白名单：
// 先 MAP * ~NOTFOUND 让所有域名解析失败，再用 EXCLUDE 逐个放行登录流程需要的主机。
func hostResolverRules() string {
	rules := []string{"MAP * ~NOTFOUND"}
	for _, host := range allowedHosts {
		rules = append(rules, "EXCLUDE "+host)
	}
	return "--host-resolver-rules=" + strings.Join(rules, ", ")
}

func watchTicket(page playwright.Page) <-chan string {
	ticketCh := make(chan string, 1)
	page.OnRequest(func(r playwright.Request) {
		ticket := matchTicket(r.URL())
		if ticket == "" {
			return
		}
		select {
		case ticketCh <- ticket:
		default: // 已经收到过 ticket，丢弃
		}
	})
	return ticketCh
}

func watchSourceId(page playwright.Page) chan playwright.Response {
	respCh := make(chan playwright.Response, 16)

	page.OnResponse(func(r playwright.Response) {
		select {
		case respCh <- r:
		default: // 队列已满，丢弃
		}
	})
	return respCh
}

// loginPageURL 拼出 CAS 登录页地址（service 会被正确 urlencode）。
func loginPageURL(service string) (string, error) {
	u, err := url.Parse("https://sso.ecnu.edu.cn/login")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("service", service)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func dropResps(ch chan playwright.Response, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-ch:
		}
	}
}

func submitLogin(page playwright.Page) error {
	submitSelectors := []string{
		`#submitBtn`,
		`button#submitBtn[nz-button]`,
		`button.login-button`,
		`button.ant-btn.login-button`,
		`button:has-text("立即登录")`,
		`//button[.//span[text()="立即登录"]]`,
	}

	var lastErr error
	for _, sel := range submitSelectors {
		if err := page.Locator(sel).Click(playwright.LocatorClickOptions{Timeout: playwright.Float(1500)}); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func fillLoginForm(page playwright.Page, opt *TicketOptions) error {
	userSelectors := []string{
		`#nameInput`,
		`input#nameInput[name="username"]`,
		`input[name="username"]`,
		`input[autocomplete="username"]`,
		`input[nz-input][placeholder*="学工号"]`,
		`input.ant-input[name="username"]`,
		`form input[name="username"]:not([readonly]):not([disabled])`,
	}
	userSel, err := waitAnyVisible(page, userSelectors, 10*time.Second)
	if err != nil {
		return fmt.Errorf("Failed to find username input: %s", err)
	}
	if err := page.Locator(userSel).Fill(opt.Account); err != nil {
		return fmt.Errorf("Failed to fill username: %s", err)
	}

	passSelectors := []string{
		`input[type="password"]`,
		`input[autocomplete="new-password"]`,
		`input[placeholder*="密码"]`,
		`form input.ant-input[type="password"]`,
		`input[nz-input][type="password"]`,
		`input[libnochinese][type="password"]`,
	}
	passSel, err := waitAnyVisible(page, passSelectors, 10*time.Second)
	if err != nil {
		return fmt.Errorf("Failed to find password input: %s", err)
	}
	if err := page.Locator(passSel).Fill(opt.Password); err != nil {
		return fmt.Errorf("Failed to fill password: %s", err)
	}

	return nil
}

// waitAnyVisible 在 deadline 内轮询一组选择器，返回第一个可见元素的选择器。
func waitAnyVisible(page playwright.Page, selectors []string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, sel := range selectors {
			err := page.Locator(sel).WaitFor(playwright.LocatorWaitForOptions{
				State:   playwright.WaitForSelectorStateVisible,
				Timeout: playwright.Float(250),
			})
			if err == nil {
				return sel, nil
			}
		}
	}
	return "", fmt.Errorf("Timed out.")
}

func matchTicket(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	return q.Get("ticket")
}

// sourceIDTGC 从一条响应的 Set-Cookie 头里精确取出 SOURCEID_TGC 的值。
func sourceIDTGC(resp playwright.Response) (string, bool) {
	values, err := resp.HeaderValues("set-cookie")
	if err != nil {
		return "", false
	}

	for _, raw := range values {
		pair, _, _ := strings.Cut(raw, ";")
		name, value, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(name) != "SOURCEID_TGC" {
			continue
		}

		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if value == "" {
			continue
		}
		return value, true
	}
	return "", false
}

// pwSession 独占管理一整套 playwright 资源（driver/browser/context/page），
// 外部只需持有 session 本身，结束时调用 Close 释放全部资源。
type pwSession struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	ctx     playwright.BrowserContext
	page    playwright.Page
}

func (s *pwSession) Close() {
	if s.page != nil {
		_ = s.page.Close()
	}
	if s.ctx != nil {
		_ = s.ctx.Close()
	}
	if s.browser != nil {
		_ = s.browser.Close()
	}
	if s.pw != nil {
		_ = s.pw.Stop()
	}
}

func newPwSession() (*pwSession, error) {
	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("Failed to start playwright: %s", err)
	}
	session := &pwSession{pw: pw}

	launchArgs := []string{
		"--lang=zh-CN",
		"--disable-blink-features=AutomationControlled",
		"--hide-scrollbars",
		"--mute-audio",
		hostResolverRules(), // 在网络层启用白名单，过滤其他域名，防止ticket被提前消费。
	}
	if noSandbox {
		launchArgs = append(launchArgs, "--no-sandbox", "--disable-dev-shm-usage")
	}
	launchOpts := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args:     launchArgs,
	}

	browser, err := pw.Chromium.Launch(launchOpts)
	if err != nil {
		_ = pw.Stop()
		return nil, fmt.Errorf("Failed to launch browser: %s", err)
	}
	session.browser = browser

	ctxOpts := playwright.BrowserNewContextOptions{
		Locale:    playwright.String("zh-CN"),
		UserAgent: playwright.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0"),
		Viewport:  &playwright.Size{Width: 1920, Height: 1080},
	}
	ctx, err := browser.NewContext(ctxOpts)
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("Failed to create browser context: %s", err)
	}
	session.ctx = ctx

	page, err := ctx.NewPage()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("Failed to create page: %s", err)
	}
	session.page = page
	return session, nil
}
