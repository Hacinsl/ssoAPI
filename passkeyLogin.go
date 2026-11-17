package ssoapi

import (
	"bytes"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net/url"
	"regexp"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"strings"
)

// parseRSAPublicKey 把 PEM 形式的 PKIX 公钥解析成 *rsa.PublicKey。
func parseRSAPublicKey(s string) (*rsa.PublicKey, error) {
	body := strings.TrimSpace(s)
	body = strings.TrimPrefix(body, "-----BEGIN PUBLIC KEY-----")
	body = strings.TrimSuffix(body, "-----END PUBLIC KEY-----")
	body = strings.Join(strings.Fields(body), "")

	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("decode public key base64: %w", err)
	}

	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not *rsa.PublicKey", k)
	}
	return pub, nil
}

// parseEd25519PrivateKey 把 KeyStore 里的私钥还原成 ed25519.PrivateKey。
func parseEd25519PrivateKey(pemStr string) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		return nil, fmt.Errorf("private key is not PEM encoded")
	}

	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
	}

	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not ed25519.PrivateKey", k)
	}
	return priv, nil
}

func aesEncrypt(s string, key []byte) []byte {
	blk, _ := aes.NewCipher(key)
	p := 16 - len(s)%16
	b := append([]byte(s), bytes.Repeat([]byte{byte(p)}, p)...)
	out := make([]byte, len(b))
	for i := 0; i < len(b); i += 16 {
		blk.Encrypt(out[i:i+16], b[i:i+16])
	}
	return out
}

func aesDecrypt(s []byte, key []byte) string {
	blk, _ := aes.NewCipher(key)
	out := make([]byte, len(s))
	for i := 0; i < len(s); i += 16 {
		blk.Decrypt(out[i:i+16], s[i:i+16])
	}
	p := int(out[len(out)-1])
	return string(out[:len(out)-p])
}

func getPublicKey() (*rsa.PublicKey, error) {
	js, err := doGetHtml("https://sso.ecnu.edu.cn/public/webauthJs/webauthn.js?v=2.0.1",
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to get public key: %w", err)
	}

	// 有些版本会把换行写成 "\\n" 转义，这里统一还原成真实换行
	src := strings.ReplaceAll(*js, `\n`, "\n")
	pemStr := regexp.MustCompile(`-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]+-----END PUBLIC KEY-----`).FindString(src)
	if pemStr == "" {
		return nil, fmt.Errorf("Failed to get public key: key not found in js")
	}

	return parseRSAPublicKey(pemStr)
}

// 37 字节：rpIdHash(32) | flags(1) | signCount(4)
func buildAuthenticatorDataForGet(rpID string, signCount uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))

	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], signCount)

	buf := make([]byte, 0, 37)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, 0x01) // UP 置位，UV 置零
	buf = append(buf, counter[:]...)
	return buf
}

// 在 Passkey 已经被使用的情况下，即使最终返回了 error，认证次数也已经被更新，所以调用者需要检查返回值是否为空，若不为空则利用返回值更新 Passkey。
func loginPasskey(opt *CasOptions) (*CasResp, error) {
	executionResp, err := casWithNothing()
	if err != nil {
		return nil, fmt.Errorf("Failed to login for %s: %w", opt.Account, err)
	}
	loginRsaPubKey, err := getPublicKey()
	if err != nil {
		return nil, fmt.Errorf("Failed to login for %s: %w", opt.Account, err)
	}

	random := make([]byte, 16)
	rand.Read(random)
	ct, _ := rsa.EncryptPKCS1v15(rand.Reader, loginRsaPubKey, []byte(base64.StdEncoding.EncodeToString(random)))

	usernameData, _ := json.Marshal(map[string]string{"username": opt.Account})
	r, err := doPostBytes("https://sso.ecnu.edu.cn/webauthn/authenticate",
		[]byte(base64.StdEncoding.EncodeToString(aesEncrypt(string(usernameData), random))), nil,
		&map[string]string{
			"Content-Type": "application/json",
			"X-CSRF-TOKEN": "csrfToken",
			"hasCrypto":    "true",
			"privateKey":   base64.StdEncoding.EncodeToString(ct),
			"Origin":       "https://sso.ecnu.edu.cn",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to login for %s: %w", opt.Account, err)
	}

	decodeR, err := base64.StdEncoding.DecodeString(string(*r))
	if err != nil {
		return nil, fmt.Errorf("Failed to decode response base64: %w", err)
	}
	decR := aesDecrypt(decodeR, random)
	authResp := new(authenticateResp)
	if err = json.Unmarshal([]byte(decR), authResp); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal response: %w", err)
	}

	authData := buildAuthenticatorDataForGet(opt.Passkey.RpId, uint32(opt.Passkey.SignCount+1))
	clientData, _ := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   authResp.Request.PublicKeyCredentialRequestOptions.Challenge,
		"origin":      "https://sso.ecnu.edu.cn",
		"crossOrigin": false,
	})
	digest := sha256.Sum256(clientData)
	toSign := make([]byte, 0, len(authData)+len(digest))
	toSign = append(toSign, authData...)
	toSign = append(toSign, digest[:]...)
	signKey, err := parseEd25519PrivateKey(opt.Passkey.PrivateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse passkey private key: %w", err)
	}
	signatureData := ed25519.Sign(signKey, toSign)

	response := map[string]any{
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		"signature":         base64.RawURLEncoding.EncodeToString(signatureData),
		"userHandle":        opt.Passkey.UserId,
	}
	credential := map[string]interface{}{
		"type":                   "public-key",
		"id":                     opt.Passkey.CredentialId,
		"response":               response,
		"clientExtensionResults": map[string]interface{}{},
	}

	finishResp, err := doPostJSON[finishResp]("https://sso.ecnu.edu.cn/webauthn/authenticate/finish",
		&map[string]interface{}{
			"requestId":    authResp.Request.RequestID,
			"credential":   credential,
			"sessionToken": authResp.Request.SessionToken,
		}, nil,
		&map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
			"X-CSRF-TOKEN": "csrfToken",
			"Content-Type": "text/plain;charset=UTF-8",
			"Origin":       "https://sso.ecnu.edu.cn",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to login for %s: %w", opt.Account, err)
	}
	if !finishResp.Success {
		return nil, fmt.Errorf("Failed to login for %s: Server returns failure", opt.Account)
	}

	casResp := CasResp{Passkey: opt.Passkey}
	casResp.Passkey.SignCount++

	loginRespCookies, err := doPostCookie("https://sso.ecnu.edu.cn/login",
		url.Values{
			"username":    {opt.Passkey.Username},
			"token":       {finishResp.SessionToken},
			"_eventId":    {"validateWebAuthn"},
			"execution":   {*executionResp.Execution},
			"geolocation": {""},
		}, nil,
		&map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
			"Origin":       "https://sso.ecnu.edu.cn",
			"Content-Type": "application/x-www-form-urlencoded",
		},
	)
	if err != nil {
		return &casResp, fmt.Errorf("Failed to login for %s: %w", opt.Account, err)
	}

	for _, c := range loginRespCookies {
		if c.Name == "SESSION" {
			casResp.Session = c.Value
			break
		}
	}

	for _, c := range loginRespCookies {
		if c.Name == "SOURCEID_TGC" {
			casResp.SourceID = c.Value
			return &casResp, nil
		}
	}

	return &casResp, fmt.Errorf("Failed to login for %s: Can not find SOURCEID_TGC", opt.Account)
}
