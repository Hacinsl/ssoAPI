package ssoapi

// 通行密钥
type KeyStore struct {
	Username      string
	DeviceName    string
	BaseUrl       string
	CredentialId  string
	RpId          string
	UserId        string
	Alg           int
	PrivateKeyPem string
	SignCount     int
	CreateAt      string
}

// https://sso.ecnu.edu.cn/webauthn/register/options 接口返回。
type registerResp struct {
	Success bool            `json:"success"`
	Request registerRequest `json:"request"`
	Actions registerActions `json:"actions"`
}

type registerActions struct {
	Finish string `json:"finish"`
}

type registerRequest struct {
	Username                           string                             `json:"username"`
	CredentialNickname                 string                             `json:"credentialNickname"`
	RequestID                          string                             `json:"requestId"`
	PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions `json:"publicKeyCredentialCreationOptions"`
	SessionToken                       string                             `json:"sessionToken"`
}

// 对应 W3C WebAuthn 的同名结构，
// 字段顺序与命名保持和规范一致，便于对照浏览器端 navigator.credentials.create()。
type publicKeyCredentialCreationOptions struct {
	RP                     relyingPartyEntity      `json:"rp"`
	User                   userEntity              `json:"user"`
	Challenge              string                  `json:"challenge"` // base64url（无 padding）
	PubKeyCredParams       []pubKeyCredParam       `json:"pubKeyCredParams"`
	ExcludeCredentials     []credentialDescriptor  `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *authenticatorSelection `json:"authenticatorSelection,omitempty"`
	Attestation            string                  `json:"attestation,omitempty"` // "none"/"indirect"/"direct"/"enterprise"
	Timeout                int                     `json:"timeout,omitempty"`     // 毫秒
	Extensions             map[string]any          `json:"extensions,omitempty"`  // 键随场景变化（appid/appidExclude/credProps…），按原样透传即可
}

type relyingPartyEntity struct {
	Name string `json:"name"`
	ID   string `json:"id"` // 即 rpId，必须是凭证所属域名的可注册后缀
}

type userEntity struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	ID          string `json:"id"` // base64url（无 padding）编码的 user handle
}

type pubKeyCredParam struct {
	Alg  int    `json:"alg"`  // COSE 算法：-7=ES256、-257=RS256、-8=EdDSA、-35/-36=ES384/ES512 等
	Type string `json:"type"` // 固定 "public-key"
}

type credentialDescriptor struct {
	Type       string   `json:"type"`                 // 固定 "public-key"
	ID         string   `json:"id"`                   // base64url（无 padding）编码的 credentialId
	Transports []string `json:"transports,omitempty"` // "usb"/"nfc"/"ble"/"internal"/"hybrid"
}

type authenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"` // "platform"/"cross-platform"
	RequireResidentKey      bool   `json:"requireResidentKey"`                // 保留 false，避免被省略后语义丢失
	ResidentKey             string `json:"residentKey,omitempty"`             // "discouraged"/"preferred"/"required"
	UserVerification        string `json:"userVerification,omitempty"`        // "required"/"preferred"/"discouraged"
}

// https://sso.ecnu.edu.cn/webauthn/register/finish 接口返回。
// 相较于 registerResp 增加服务端对凭证的核验结果：
//   - response：认证器原始输出的原样回显；
//   - registration：服务端解析并落库的凭证记录（公钥、userHandle、signCount 等）；
//   - attestationTrusted：attestation 是否通过验签；
//   - authData：服务端把 authenticatorData 字节流字段化后的视图。
type finishResp struct {
	Success            bool             `json:"success"`
	Request            registerRequest  `json:"request"`
	Response           finishResponse   `json:"response"`
	Registration       registrationInfo `json:"registration"`
	AttestationTrusted bool             `json:"attestationTrusted"`
	AuthData           authData         `json:"authData"`
	Username           string           `json:"username"`
	SessionToken       string           `json:"sessionToken"`
}

type finishResponse struct {
	RequestID    string           `json:"requestId"`
	Credential   finishCredential `json:"credential"`
	SessionToken string           `json:"sessionToken"`
}

type finishCredential struct {
	ID                     string                           `json:"id"` // base64url（无 padding）
	Response               attestationResponse              `json:"response"`
	ClientExtensionResults credentialClientExtensionResults `json:"clientExtensionResults"`
	Type                   string                           `json:"type"` // 固定 "public-key"
}

type attestationResponse struct {
	AttestationObject string   `json:"attestationObject"` // 运行时无意义，不再解码
	ClientDataJSON    string   `json:"clientDataJSON"`    // 运行时无意义，不再解码
	Transports        []string `json:"transports"`
}

type credentialClientExtensionResults struct {
	CredProps *credentialPropertiesOutput `json:"credProps,omitempty"` // 仅当 options 里请求了 credProps
}

type credentialPropertiesOutput struct {
	RK bool `json:"rk"` // 凭证是否为可发现凭证（resident key）
}

type registrationInfo struct {
	UserIdentity       userEntity           `json:"userIdentity"`
	CredentialNickname string               `json:"credentialNickname"`
	Transports         []string             `json:"transports"`
	RegistrationTime   float64              `json:"registrationTime"` // Unix 秒，带小数（如 1794394439.746），不能用 int64
	Credential         registeredCredential `json:"credential"`
	Username           string               `json:"username"`
}

type registeredCredential struct {
	CredentialID   string `json:"credentialId"`   // base64url（无 padding）
	UserHandle     string `json:"userHandle"`     // base64url（无 padding）的 user.id
	PublicKeyCose  string `json:"publicKeyCose"`  // base64url（无 padding）编码的 COSE_Key
	SignatureCount int    `json:"signatureCount"` // 注册时为 0
}

type authData struct {
	RPIDHash               string                  `json:"rpIdHash"` // hex
	Flags                  authDataFlags           `json:"flags"`
	SignatureCounter       uint32                  `json:"signatureCounter"`
	AttestedCredentialData *attestedCredentialData `json:"attestedCredentialData,omitempty"` // AT 位置位时才存在
}

type authDataFlags struct {
	Value byte `json:"value"` // 原始字节，如 0x45 = UP|UV|AT
	UP    bool `json:"UP"`    // 0x01 用户在场
	UV    bool `json:"UV"`    // 0x04 用户已通过手势/生物识别验证
	BE    bool `json:"BE"`    // 0x08 备份可用（backup eligible）
	BS    bool `json:"BS"`    // 0x10 当前处于备份状态
	AT    bool `json:"AT"`    // 0x40 含 attestedCredentialData
	ED    bool `json:"ED"`    // 0x80 含扩展数据
}

type attestedCredentialData struct {
	AAGUID       string `json:"aaguid"`       // hex（32 字符，无连字符）
	CredentialID string `json:"credentialId"` // hex
	PublicKey    string `json:"publicKey"`    // hex 编码的 COSE_Key 原始字节
}

// https://sso.ecnu.edu.cn/webauthn/authenticate 接口返回。
type authenticateResp struct {
	Success      bool                `json:"success"`
	Request      authenticateRequest `json:"request"`
	Actions      authenticateActions `json:"actions"`
	SessionToken string              `json:"sessionToken,omitempty"`
}

type authenticateActions struct {
	Finish string `json:"finish"` // 例如 "/webauthn/authenticate/finish"
}

type authenticateRequest struct {
	RequestID                         string                            `json:"requestId"`
	PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions `json:"publicKeyCredentialRequestOptions"`
	SessionToken                      string                            `json:"sessionToken,omitempty"`
}

// 对应 W3C WebAuthn 的同名结构，
type publicKeyCredentialRequestOptions struct {
	Challenge        string                 `json:"challenge"`                  // base64url（无 padding）
	RPID             string                 `json:"rpId"`                       // 如 "sso.ecnu.edu.cn"
	AllowCredentials []credentialDescriptor `json:"allowCredentials,omitempty"` // 允许的凭证列表，空表示任意可发现凭证
	UserVerification string                 `json:"userVerification,omitempty"` // "required"/"preferred"/"discouraged"
	Timeout          int                    `json:"timeout,omitempty"`          // 毫秒
	Extensions       map[string]any         `json:"extensions,omitempty"`       // 键随场景变化（appid 等），按原样透传
}

// 用于 CBOR 编码
type attestationObject struct {
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`
	AuthData []byte         `cbor:"authData"`
}
