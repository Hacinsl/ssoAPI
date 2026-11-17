package ssoapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func doGet[T any](u string, form *url.Values, cookies *map[string]string, headers *map[string]string) (*T, error) {
	resp, err := doGetResp(u, form, cookies, headers)
	if err != nil {
		return nil, err
	}

	r, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response for %s: %w", u, err)
	}

	result := new(T)
	err = json.Unmarshal(r, result)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal response for %s: %w", u, err)
	}
	return result, nil
}

func doGetHtml(u string, headers *map[string]string) (*string, error) {
	resp, err := doGetResp(u, nil, nil, headers)
	if err != nil {
		return nil, err
	}

	r, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response for %s: %w", u, err)
	}

	html := string(r)
	return &html, nil
}

func doGetLoaction(u string, form *url.Values, cookies *map[string]string, headers *map[string]string) (*url.URL, error) {
	resp, err := doGetResp(u, form, cookies, headers)
	if err != nil {
		return nil, err
	}

	return resp.Location()
}

func doGetCookie(u string, form *url.Values, cookies *map[string]string, headers *map[string]string) ([]*http.Cookie, error) {
	resp, err := doGetResp(u, form, cookies, headers)
	if err != nil {
		return nil, err
	}

	return resp.Cookies(), nil
}

// doGetResp 直接发送给定的请求体，返回一个 *http.Response。
// 返回的 Body 是一个可重复读的内存缓冲，无需 Close。
func doGetResp(u string, form *url.Values, cookies *map[string]string, headers *map[string]string) (*http.Response, error) {
	pu, _ := url.Parse(u)
	if form != nil {
		pu.RawQuery = form.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, pu.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create request for %s: %w", pu.String(), err)
	}

	if cookies != nil {
		for k, v := range *cookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
	}

	if headers != nil {
		for k, v := range *headers {
			req.Header.Add(k, v)
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if EnableDebugOutput {
		dumpRequest(req)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to get %s: %w", u, err)
	}

	// 把 body 换成与 TCP 连接无关的内存缓冲，使调用方仍能按 *http.Response 惯例读取
	r, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to read response for %s: %w", u, err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(r))

	if EnableDebugOutput {
		dumpResponse(resp)
	}

	return resp, nil
}
