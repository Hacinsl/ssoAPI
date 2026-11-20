package ssoapi

import (
	"fmt"
	"io"
	"net/url"
	"regexp"

	httputils "github.com/Hacinsl/httpUtils"
)

func fallback(opt *CasOptions) (*CasOptions, error) {
	if opt.Passkey != (KeyStore{}) {
		logInfo("Fallback: Try to refresh with Passkey.")
		r, err := loginPasskey(opt)
		if err != nil {
			logError("Fallback: Passkey login failed: %s", err)
			return nil, err
		}
		opt.SourceID = r.SourceID
		opt.Passkey = r.Passkey
		logInfo("Fallback: Refreshed with Passkey, get SourceID: %s", opt.SourceID)
		return opt, nil
	}
	if opt.Account != "" && opt.Password != "" {
		logInfo("Fallback: Try to refresh with Account.")
		r, err := casWithAccount(opt)
		if err != nil {
			logError("Fallback: Account login failed: %s", err)
			return nil, err
		}
		opt.SourceID = r.SourceID
		logInfo("Fallback: Refreshed with Account, get SourceID: %s", opt.SourceID)
		return opt, nil
	}
	logError("Fallback: Neither Account nor Passkey provided.")
	return nil, fmt.Errorf("Neither Account nor Passkey provided")
}

// 使用 CasOption 中的 SourceID，返回有效 SSO 登录态 Session。无法取得 Session 时报错。
func casWithTgc(opt *CasOptions) (*CasResp, error) {
	logInfo("Start casWithTgc: SourceID = %s", opt.SourceID)
	fallbacked := false

Fallback:
	logDebug("Request cas login session: %s", "https://sso.ecnu.edu.cn/login")
	resp, err := httputils.GetResp("https://sso.ecnu.edu.cn/login", nil,
		&map[string]string{
			"SOURCEID_TGC": opt.SourceID,
		},
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0",
		},
	)
	if err != nil {
		logError("Failed to get cas login session: %s", err)
		return nil, fmt.Errorf("Failed to get cas login session: %w", err)
	}

	for _, c := range resp.Cookies() {
		if c.Name == "SESSION" {
			logInfo("Get SESSION: %s", c.Value)
			return &CasResp{Session: c.Value}, nil
		}
	}
	if fallbacked {
		logError("Failed to get cas login session: Can not find SESSION")
		return nil, fmt.Errorf("Failed to get cas login session: Can not find SESSION")
	}
	logWarn("Can not find SESSION, try to fallback.")
	fallbacked = true
	opt, err = fallback(opt)
	if err != nil {
		logError("Failed to fallback after one failure: %s", err)
		return nil, fmt.Errorf("Failed to fallback after one failure: %w", err)
	}
	logInfo("Fallback done, retry with new SourceID: %s", opt.SourceID)
	goto Fallback
}

// 使用 CasOption 中的 SourceID，返回匿名 Session，有效 Ticket/Location。无法取得 Ticket 时报错。
func casWithTgcForService(opt *CasOptions) (*CasResp, error) {
	logInfo("Start casWithTgcForService: Service = %s, SourceID = %s", opt.Service, opt.SourceID)
	fallbacked := false

Fallback:
	logDebug("Request cas login session: %s", "https://sso.ecnu.edu.cn/login")
	resp, err := httputils.GetResp("https://sso.ecnu.edu.cn/login",
		&url.Values{
			"service": {opt.Service},
		},
		&map[string]string{
			"SOURCEID_TGC": opt.SourceID,
		},
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0",
		},
	)
	if err != nil {
		logError("Failed to get cas login session: %s", err)
		return nil, fmt.Errorf("Failed to get cas login session: %w", err)
	}

	r := new(CasResp)
	r.Location, _ = resp.Location()
	if r.Location != nil {
		logDebug("Get Location: %s", r.Location.String())
		r.Ticket = r.Location.Query().Get("ticket")
		for _, c := range resp.Cookies() {
			if c.Name == "SESSION" {
				r.Session = c.Value
			}
		}
	}
	if r.Ticket == "" {
		if fallbacked {
			logError("Failed to get cas ticket: Can not find ticket")
			return nil, fmt.Errorf("Failed to get cas ticket: Can not find ticket")
		}
		logWarn("Can not find ticket, try to fallback.")
		fallbacked = true
		opt, err = fallback(opt)
		if err != nil {
			logError("Failed to fallback after one failure: %s", err)
			return nil, fmt.Errorf("Failed to fallback after one failure: %w", err)
		}
		logInfo("Fallback done, retry with new SourceID: %s", opt.SourceID)
		goto Fallback
	}
	logInfo("Get CasResp: SourceID = %s, Ticket = %s, Session = %s", opt.SourceID, r.Ticket, r.Session)
	return r, nil
}

// 不使用任何参数，返回匿名 Session，Execution。
func casWithNothing() (*CasResp, error) {
	loginURL := "https://sso.ecnu.edu.cn/login"
	logInfo("Start casWithNothing: Use login URL %s", loginURL)

	resp, err := httputils.GetResp(loginURL, nil, nil,
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
		},
	)
	if err != nil {
		logError("Failed to get execution: %s", err)
		return nil, fmt.Errorf("Failed to get execution: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logError("Failed to read login page: %s", err)
		return nil, fmt.Errorf("Failed to read login page: %w", err)
	}
	page := string(body)

	value := regexp.MustCompile(`<p id="login-page-flowkey">([^<]*)</p>`).FindStringSubmatch(page)
	if value == nil {
		logError("Failed to get execution: flowkey not found in login page")
		return nil, fmt.Errorf("Failed to get execution: flowkey not found in login page")
	}
	execution := value[1]
	logDebug("Get execution: %s", execution)

	var riskSystemSwitch string
	if m := regexp.MustCompile(`<p id="riskSystemSwitch">([^<]*)</p>`).FindStringSubmatch(page); m != nil {
		riskSystemSwitch = m[1]
	}
	if riskSystemSwitch == "USTC" {
		logError("This login flow requires browser risk verification")
		return nil, fmt.Errorf("This login flow requires browser risk verification")
	}

	r := &CasResp{Execution: &execution}
	for _, c := range resp.Cookies() {
		if c.Name == "SESSION" {
			r.Session = c.Value
		}
	}
	logInfo("Get CasResp: Session = %s, Execution = %s", r.Session, *r.Execution)
	return r, nil
}
