package ssoapi

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"

	httputils "github.com/Hacinsl/httpUtils"
)

// 对 ECNU 统一认证而言，oauth是cas单点登录后的可选流程。部分应用（如sso-self）由oauth尝试取得授权，发现会话无效后重定向到登录页通过cas取得sourceId，而后发送
//  https://sso.ecnu.edu.cn/oauth2.0/authorize?response_type=code&client_id=<实际的client_id>&redirect_uri=<实际的callback回调地址>&scope=ECNU-Basic
// 并携带sourceId得到oauth的code。
// 本文件实现由cas sourceId获取oauth code的流程。oauth client id由API调用方提供。

type OauthOptions struct {
	SourceId    string
	ClientId    string
	RedirectUri string
}

type OauthResp struct {
	Code    string
	State   string
	Session string
}

// 使用 OauthOption 中的 SourceID，返回客户端生成的有效 State，来自 CAS 的匿名 Session 和有效 Code。
func oauthWithTgc(opt *OauthOptions) (*OauthResp, error) {
	logInfo("Start oauthWithTgc: SourceID = %s, ClientId = %s, RedirectUri = %s", opt.SourceId, opt.ClientId, opt.RedirectUri)
	OauthResp := new(OauthResp)

	// 生成随机state
	b := make([]byte, 32)
	rand.Read(b)
	OauthResp.State = base64.URLEncoding.EncodeToString(b)
	logDebug("Generate oauth state: %s", OauthResp.State)

	// service 的参数顺序必须与 CAS 的规范化顺序一致：
	// client_id -> redirect_uri -> response_type -> client_name。
	// 不能交给 url.Values.Encode()，它会按 key 排序（把 client_name 排到 redirect_uri 前），
	// 这样签出的 ST 在 callbackAuthorize 会被 CAS 判为无效并返回 500。
	service := "https://sso.ecnu.edu.cn/oauth2.0/callbackAuthorize" +
		"?client_id=" + url.QueryEscape(opt.ClientId) +
		"&redirect_uri=" + url.QueryEscape(opt.RedirectUri) +
		"&response_type=code" +
		"&client_name=CasOAuthClient"
	logDebug("Build oauth service: %s", service)

	casResp, err := casWithTgcForService(&CasOptions{SourceID: opt.SourceId, Service: service})
	if err != nil {
		logError("Failed to get cas ticket for oauth: %s", err)
		return nil, err
	}
	OauthResp.Session = casResp.Session
	logDebug("Get cas SESSION: %s", OauthResp.Session)

	// 把授权请求注册进cas session，无需响应。
	// 同样手拼（顺序同浏览器），form 传 nil，避免被 Encode() 重排。
	authzURL := "https://sso.ecnu.edu.cn/oauth2.0/authorize" +
		"?response_type=code" +
		"&client_id=" + url.QueryEscape(opt.ClientId) +
		"&scope=read%20write" +
		"&state=" + url.QueryEscape(OauthResp.State) +
		"&redirect_uri=" + url.QueryEscape(opt.RedirectUri)
	logDebug("Register authorize request: %s", authzURL)
	if _, err := httputils.GetLoaction(authzURL, nil,
		&map[string]string{
			"SOURCEID_TGC": opt.SourceId,
			"SESSION":      OauthResp.Session,
		}, nil); err != nil {
		logError("Failed to register authorize request: %s", err)
		return nil, fmt.Errorf("Failed to register authorize request: %w", err)
	}

	// casLocation 是上一步 /login 的 302 目标（callbackAuthorize?…&ticket=ST-…），
	// 从这里继续跳回 callbackAuthorize → authorize → sso-self，最后拿到 code。
	u, err := httputils.GetLoaction(casResp.Location.String(), nil,
		&map[string]string{
			"SOURCEID_TGC": opt.SourceId,
			"SESSION":      OauthResp.Session,
		},
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0",
		},
	)
	if err != nil {
		logWarn("Failed to follow cas location %s: %s", casResp.Location.String(), err)
		if u == nil {
			return nil, fmt.Errorf("Failed to follow cas location %s: %w", casResp.Location.String(), err)
		}
	}

	logDebug("Follow oauth location: %s", u.String())
	u, err = httputils.GetLoaction(u.String(), nil,
		&map[string]string{
			"SOURCEID_TGC": opt.SourceId,
			"SESSION":      OauthResp.Session,
		},
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0",
		},
	)
	if err != nil {
		logError("Failed to get location for %s: %s", opt.ClientId, err)
		return nil, fmt.Errorf("Failed to get location for %s: %w", opt.ClientId, err)
	}

	OauthResp.Code = u.Query().Get("code")
	logInfo("Get OauthResp: Code = %s, State = %s, Session = %s", OauthResp.Code, OauthResp.State, OauthResp.Session)
	return OauthResp, nil
}
