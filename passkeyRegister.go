package ssoapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"time"

	httputils "github.com/Hacinsl/httpUtils"
	"github.com/fxamacker/cbor/v2"
)

// COSE 公钥编码
func coseEd25519Raw(pub []byte) []byte {
	b := []byte{
		0xa4,       // map(4)
		0x01, 0x01, // 1: 1
		0x03, 0x27, // 3: -8
		0x20, 0x06, // -1: 6
		0x21, 0x58, 0x20, // -2: bstr(32)
	}
	return append(b, pub...)
}

// buildAuthenticatorDataForCreate 构造注册流程（navigator.credentials.create）中
// authenticatorData 的完整字节序列：
//
//	rpIdHash(32) || flags(1) || signCount(4, big-endian) || attestedCredentialData
//
// 其中 attestedCredentialData =
//
//	aaguid(16) || credentialIdLen(2, big-endian) || credentialId || COSE public key
//
// 与断言流程（getAssertion）的 authenticatorData 相比，这里多了 attestedCredentialData，
// 因此 flags 必须置上 AT 位；注册时的 UP 位同理恒置。
//
// cosePublicKey 必须是已完成 CBOR 编码的 COSE_Key 字节（COSE key 本身就是一次 CBOR
// 序列化，这里直接内联、不再套 bstr 头），可直接传 coseEd25519Raw 的返回值，
// 等价于 Python 版里对 cose_public_key 字典做的 _cbor_dumps。
func buildAuthenticatorDataForCreate(rpID string, signCount uint32, credentialID []byte, cosePublicKey []byte) []byte {
	var flagUserPresent byte = 0x01  // UP：用户在场（已由用户完成手势验证）
	var flagAttestedData byte = 0x40 // AT：authenticatorData 内含 attestedCredentialData
	var aaguidZero [16]byte          // aaguidZero 是「认证器型号未知/不想暴露」时使用的 16 字节全零 AAGUID。
	rpIDHash := sha256.Sum256([]byte(rpID))

	// 预分配以免多次扩容：32 + 1 + 4 + 16 + 2 + len(credId) + len(coseKey)
	payload := make([]byte, 0, sha256.Size+1+4+len(aaguidZero)+2+len(credentialID)+len(cosePublicKey))
	payload = append(payload, rpIDHash[:]...)
	payload = append(payload, flagUserPresent|flagAttestedData)
	payload = binary.BigEndian.AppendUint32(payload, signCount)
	payload = append(payload, aaguidZero[:]...)
	// 规范限定 credentialIdLength ≤ 1023，这里 uint16 足够；超长会被截断
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(credentialID)))
	payload = append(payload, credentialID...)
	payload = append(payload, cosePublicKey...)
	return payload
}

func serializePrivateKeyPEM(priv any) string {
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

// 以 Data 结尾的变量默认类型为 byte[]
func registerPasskey(opt *CasOptions) (*CasResp, error) {
	logInfo("Start registerPasskey: Account = %s, SourceID = %s", opt.Account, opt.SourceID)
	var key KeyStore
	key.Username = opt.Account
	key.DeviceName = "ssoAPI" + time.Now().Format("2006-01-02_15-04-05")
	key.BaseUrl = "https://sso.ecnu.edu.cn/"
	key.SignCount = 0
	logDebug("Register device name: %s", key.DeviceName)

	// 注册通行密钥需要一个登录态 SSO Session。
	casResp, err := casWithTgc(opt)
	if err != nil {
		logError("Failed to register for %s: %s", opt.Account, err)
		return nil, fmt.Errorf("Failed to register for %s: %w", opt.Account, err)
	}
	logDebug("Get SESSION for register: %s", casResp.Session)

	// 必须先加载管理页，否则 register 会返回 operation not allowed。
	logDebug("Load passkey management page.")
	resp, err := httputils.GetResp("https://sso.ecnu.edu.cn/account?skipCustom=true", nil,
		&map[string]string{
			"SOURCEID_TGC": opt.SourceID,
			"SESSION":      casResp.Session,
		},
		&map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
			"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	)
	if err != nil {
		logError("Failed to load passkey management page: %s", err)
		return nil, fmt.Errorf("Failed to load passkey management page: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		logError("Failed to load passkey management page: unexpected status %d", resp.StatusCode)
		return nil, fmt.Errorf("Failed to load passkey management page: unexpected status %d", resp.StatusCode)
	}
	logDebug("Passkey management page status: %d", resp.StatusCode)

	logDebug("Request webauthn register for %s.", opt.Account)
	r, err := httputils.PostForm[registerResp]("https://sso.ecnu.edu.cn/webauthn/register",
		&url.Values{
			"username":           {opt.Account},
			"displayName":        {opt.Account},
			"credentialNickname": {key.DeviceName},
			"requireResidentKey": {"false"},
			"sessionToken":       {"null"},
		},
		&map[string]string{
			"SOURCEID_TGC": opt.SourceID,
			"SESSION":      casResp.Session,
		},
		&map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
			"Accept":       "*/*",
			"Referer":      "https://sso.ecnu.edu.cn/?skipCustom=true",
			"X-CSRF-TOKEN": "csrfToken",
			"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
			"Origin":       "https://sso.ecnu.edu.cn",
		},
	)
	if err != nil {
		logError("Failed to register for %s: %s", opt.Account, err)
		return nil, fmt.Errorf("Failed to register for %s: %w", opt.Account, err)
	}
	key.RpId = r.Request.PublicKeyCredentialCreationOptions.RP.ID
	key.UserId = r.Request.PublicKeyCredentialCreationOptions.User.ID
	key.Alg = -8
	logDebug("Get register requestId: %s, rpId: %s", r.Request.RequestID, key.RpId)

	random := make([]byte, 32)
	rand.Read(random)
	key.CredentialId = base64.RawURLEncoding.EncodeToString(random)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	coseRaw := coseEd25519Raw(pub)
	key.PrivateKeyPem = serializePrivateKeyPEM(priv)

	clientData, _ := json.Marshal(&map[string]interface{}{
		"type":        "webauthn.create",
		"challenge":   r.Request.PublicKeyCredentialCreationOptions.Challenge,
		"origin":      "https://sso.ecnu.edu.cn",
		"crossOrigin": false,
	})

	authData := buildAuthenticatorDataForCreate(r.Request.PublicKeyCredentialCreationOptions.RP.ID, 0, []byte(key.CredentialId), coseRaw)
	attestationData, _ := cbor.Marshal(&attestationObject{
		Fmt:      "none",
		AttStmt:  map[string]any{},
		AuthData: authData,
	})

	response := map[string]string{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attestationData),
		"clientDataJSON":    base64.RawStdEncoding.EncodeToString(clientData),
	}
	credential := map[string]interface{}{
		"type":                   "public-key",
		"id":                     key.CredentialId,
		"response":               response,
		"clientExtensionResults": map[string]any{},
	}

	f, err := httputils.PostJSON[finishResp]("https://sso.ecnu.edu.cn/webauthn/register/finish",
		&map[string]interface{}{
			"requestId":    r.Request.RequestID,
			"credential":   credential,
			"sessionToken": r.Request.SessionToken,
		},
		&map[string]string{
			"SOURCEID_TGC": opt.SourceID,
			"SESSION":      casResp.Session,
		},
		&map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
			"Accept":       "*/*",
			"Referer":      "https://sso.ecnu.edu.cn/?skipCustom=true",
			"X-CSRF-TOKEN": "csrfToken",
			"Content-Type": "text/plain;charset=UTF-8",
			"Origin":       "https://sso.ecnu.edu.cn",
		},
	)
	if err != nil {
		logError("Failed to finish registration for %s: %s", opt.Account, err)
		return nil, fmt.Errorf("Failed to finish registration for %s: %w", opt.Account, err)
	}
	if f.Success != true {
		logError("Failed to finish registration for %s: server rejected the credential", opt.Account)
		return nil, fmt.Errorf("Failed to finish registration for %s: server rejected the credential", opt.Account)
	}

	key.CreateAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	logInfo("Get CasResp: CredentialId = %s, RpId = %s, CreateAt = %s", key.CredentialId, key.RpId, key.CreateAt)

	return &CasResp{Passkey: key}, nil
}
