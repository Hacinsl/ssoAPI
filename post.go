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

// debugDumpHeaders 按 key 排序打印一组 header，避免 map 遍历顺序随机导致
// 多次请求的输出难以对比。同名多值 header 会逐行打印。
// func debugDumpHeaders(title string, h http.Header) {
// 	keys := make([]string, 0, len(h))
// 	for k := range h {
// 		keys = append(keys, k)
// 	}
// 	sort.Strings(keys)
// 	fmt.Printf("--- %s ---\n", title)
// 	for _, k := range keys {
// 		for _, v := range h[k] {
// 			fmt.Printf("%s: %s\n", k, v)
// 		}
// 	}
// }

// doPostJSON 把 payload 序列化为 JSON 后提交，把返回体反序列化为给定的类型。
func doPostJSON[T any](u string, payload interface{}, cookies *map[string]string, headers *map[string]string) (*T, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal json: %w", err)
	}

	r, err := doPostBytes(u, data, cookies, headers)
	if err != nil {
		return nil, err
	}

	result := new(T)
	err = json.Unmarshal(*r, result)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal response for %s: %w", u, err)
	}
	return result, nil
}

// doPostForm 把 form 编码为表单后提交，把返回体反序列化为给定的类型。
func doPostForm[T any](u string, form *url.Values, cookies *map[string]string, headers *map[string]string) (*T, error) {
	r, err := doPostBytes(u, []byte(form.Encode()), cookies, headers)
	if err != nil {
		return nil, err
	}

	result := new(T)
	err = json.Unmarshal(*r, result)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal response for %s: %w", u, err)
	}
	return result, nil
}

// doPostCookie 把 form 编码为表单后提交，取回响应里的 Set-Cookie。
func doPostCookie(u string, form url.Values, cookies *map[string]string, headers *map[string]string) ([]*http.Cookie, error) {
	resp, err := doPostResp(u, []byte(form.Encode()), cookies, headers)
	if err != nil {
		return nil, err
	}

	return resp.Cookies(), nil
}

// doPostBytes 直接发送给定的请求体，返回返回体。
func doPostBytes(u string, body []byte, cookies *map[string]string, headers *map[string]string) (*[]byte, error) {
	resp, err := doPostResp(u, body, cookies, headers)
	if err != nil {
		return nil, err
	}

	r, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response for %s: %w", u, err)
	}

	return &r, nil
}

// doPostResp 直接发送给定的请求体，返回一个 *http.Response。
// 返回的 Body 是一个可重复读的内存缓冲，无需 Close。
func doPostResp(u string, body []byte, cookies *map[string]string, headers *map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("Failed to create request for %s: %w", u, err)
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
		return nil, fmt.Errorf("Failed to post %s: %w", u, err)
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

func dumpRequest(req *http.Request) {
	fmt.Println()
	fmt.Printf("[%s] %s\n", req.Method, req.URL.String())

	fmt.Println("---Request Headers---")
	if req.Header != nil {
		for k, h := range req.Header {
			for _, v := range h {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
	}

	fmt.Println("---Request Cookies---")
	if req.Cookies() != nil {
		for _, v := range req.Cookies() {
			fmt.Printf("%s: %s\n", v.Name, v.Value)
		}
	}

	fmt.Println("---Request Body---")
	if req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			body, _ := io.ReadAll(rc)
			rc.Close()
			fmt.Printf("%s\n", body)
		} else {
			fmt.Printf("(Failed to read request body: %v)\n", err)
		}
	} else if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		fmt.Printf("%s\n", body)
	} else {
		fmt.Println("(empty)")
	}
}

func dumpResponse(resp *http.Response) {
	fmt.Println()
	// 手工构造的 Response 可能没有 Request，此时只打印状态行。
	if resp.Request != nil {
		fmt.Printf("[%s] %s %s\n", resp.Request.Method, resp.Status, resp.Request.URL.String())
	} else {
		fmt.Printf("[%s]\n", resp.Status)
	}

	fmt.Println("---Response Headers---")
	if resp.Header != nil {
		for k, h := range resp.Header {
			for _, v := range h {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
	}

	fmt.Println("---Response Cookies---")
	if resp.Cookies() != nil {
		for _, v := range resp.Cookies() {
			fmt.Printf("%s: %s\n", v.Name, v.Value)
		}
	}

	fmt.Println("---Response Body---")

	if resp.Body == nil {
		fmt.Println("(empty)")
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	fmt.Printf("%s\n", body)
}
