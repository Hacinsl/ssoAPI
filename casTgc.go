package ssoapi

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
)

func fallback(opt *CasOptions) (*CasOptions, error) {
	if opt.Passkey != (KeyStore{}) {
		r, err := loginPasskey(opt)
		if err != nil {
			return nil, err
		}
		opt.SourceID = r.Session
		return opt, nil
	}
	if opt.Account != "" && opt.Password != "" {
		r, err := casWithAccount(opt)
		if err != nil {
			return nil, err
		}
		opt.SourceID = r.Session
		return opt, nil
	}
	return nil, fmt.Errorf("Neither Account nor Passkey provided")
}

// 使用 CasOption 中的 SourceID，返回有效 SSO 登录态 Session。无法取得 Session 时报错。
func casWithTgc(opt *CasOptions) (*CasResp, error) {
	fallbacked := false

Fallback:
	resp, err := doGetResp("https://sso.ecnu.edu.cn/login", nil,
		&map[string]string{
			"SOURCEID_TGC": opt.SourceID,
		},
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to get cas login session: %w", err)
	}

	for _, c := range resp.Cookies() {
		if c.Name == "SESSION" {
			return &CasResp{Session: c.Value}, nil
		}
	}
	if fallbacked {
		return nil, fmt.Errorf("Failed to get cas login session: Can not find SESSION")
	}
	fallbacked = true
	opt, err = fallback(opt)
	if err != nil {
		return nil, fmt.Errorf("Failed to fallback after one failure: %w", err)
	}
	goto Fallback
}

// 使用 CasOption 中的 SourceID，返回匿名 Session，有效 Ticket/Location。无法取得 Ticket 时报错。
func casWithTgcForService(opt *CasOptions) (*CasResp, error) {
	fallbacked := false

Fallback:
	resp, err := doGetResp("https://sso.ecnu.edu.cn/login",
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
		return nil, fmt.Errorf("Failed to get cas login session: %w", err)
	}

	r := new(CasResp)
	r.Location, _ = resp.Location()
	r.Ticket = r.Location.Query().Get("ticket")
	for _, c := range resp.Cookies() {
		if c.Name == "SESSION" {
			r.Session = c.Value
		}
	}
	if r.Ticket == "" {
		if fallbacked {
			return nil, fmt.Errorf("Failed to get cas ticket: Can not find ticket")
		}
		fallbacked = true
		opt, err = fallback(opt)
		if err != nil {
			return nil, fmt.Errorf("Failed to fallback after one failure: %w", err)
		}
		goto Fallback
	}
	return r, nil
}

// 不使用任何参数，返回匿名 Session，Execution。
func casWithNothing() (*CasResp, error) {
	loginURL := "https://sso.ecnu.edu.cn/login"

	resp, err := doGetResp(loginURL, nil, nil,
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to get execution: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read login page: %w", err)
	}
	page := string(body)

	value := regexp.MustCompile(`<p id="login-page-flowkey">([^<]*)</p>`).FindStringSubmatch(page)
	if value == nil {
		return nil, fmt.Errorf("Failed to get execution: flowkey not found in login page")
	}
	execution := value[1]

	var riskSystemSwitch string
	if m := regexp.MustCompile(`<p id="riskSystemSwitch">([^<]*)</p>`).FindStringSubmatch(page); m != nil {
		riskSystemSwitch = m[1]
	}
	if riskSystemSwitch == "USTC" {
		return nil, fmt.Errorf("This login flow requires browser risk verification")
	}

	r := &CasResp{Execution: &execution}
	for _, c := range resp.Cookies() {
		if c.Name == "SESSION" {
			r.Session = c.Value
		}
	}

	return r, nil
}
