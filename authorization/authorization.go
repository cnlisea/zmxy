package authorization

/* 芝麻信用授权 */

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/cnlisea/zmxy/utils"
)

var DecryptionFailed error = errors.New("decryption failed")
var ErrorNetwork = errors.New("network error!")
var ErrorInvalidData = errors.New("invalid response data!")
var ErrorForgedData = errors.New("forged response data!")
var ErrorEncryptionFailed = errors.New("encryption failed!")

type AuthZmApi struct {
	identityType   string
	identityParams map[string]string
	bizParams      map[string]string
}

//按照身份证+姓名进行授权
func NewAuth(query map[string]string) *AuthZmApi {
	auth := &AuthZmApi{
		identityType: "2",
	}

	return auth.init(query)
}

//按照手机号进行授权
func NewAuthByPhone(query map[string]string) *AuthZmApi {
	auth := &AuthZmApi{
		identityType: "1",
	}

	return auth.init(query)
}

//通过芝麻信用开放账号ID授权
func NewAuthByOpenId(query map[string]string) *AuthZmApi {
	auth := &AuthZmApi{
		identityType: "0",
	}
	return auth.init(query)
}

func (this *AuthZmApi) init(query map[string]string) *AuthZmApi {
	this.identityParams = query
	this.bizParams = map[string]string{
		"auth_code":   "M_APPSDK",
		"channelType": "app",
	}
	return this
}

func (this *AuthZmApi) ExDataSet(data string) *AuthZmApi {
	if "" != data {
		this.bizParams["state"] = data
	}
	return this
}

func (this *AuthZmApi) GetParams() map[string]string {
	params := make(map[string]string, 10)
	params["identity_type"] = this.identityType
	if this.identityParams != nil && len(this.identityParams) > 0 {
		json, err := json.Marshal(this.identityParams)
		if err == nil {
			params["identity_param"] = string(json)
		}
	}
	if this.bizParams != nil && len(this.bizParams) > 0 {
		json, err := json.Marshal(this.bizParams)
		if err == nil {
			params["biz_params"] = string(json)
		}
	}
	return params
}

func (this *AuthZmApi) BuildAuthorizationInfo() (string, string, error) {
	query := utils.BuildQuery(this.GetParams())
	if "" == query || 0 == len(query) {
		return "", "", ErrorEncryptionFailed
	}
	encrypted, err := utils.Encrypt(query)
	if err != nil {
		return "", "", ErrorEncryptionFailed
	}
	signature := utils.Sign(query)
	return encrypted, signature, nil
}

type AuthorizeResponse struct {
	success      bool        `json:"success"`
	errorCode    string      `json:"error_code"`
	errorMessage string      `json:"error_message"`
	openId       string      `json:"open_id"`
	appId        string      `json:"app_id"`
	state        interface{} `json:"state"`
}

func DecryptParam(Param string, result *AuthorizeResponse) *AuthorizeResponse {
	decryptedQuery := utils.DecryptRSA(utils.DecryptBase64(Param))
	if nil == decryptedQuery {
		return result.failSetErr(DecryptionFailed)
	}

	return result.analysisAuthQuery(decryptedQuery)
}

//------------------------------------------------------------------------------------------
//  AuthorizeResponse methods
//------------------------------------------------------------------------------------------
func (this *AuthorizeResponse) OpenIdGet() string {
	return this.openId
}

func (this *AuthorizeResponse) IsSuccess() bool {
	return this.success
}

func (this *AuthorizeResponse) StateGet() interface{} {
	return this.state
}

func (this *AuthorizeResponse) ErrDesc() string {
	if this.IsSuccess() {
		return ""
	}

	return this.errorCode + "==>" + this.errorMessage
}

func (this *AuthorizeResponse) failSet(err string) *AuthorizeResponse {
	this.errorMessage = err
	return this
}

func (this *AuthorizeResponse) failSetErr(err error) *AuthorizeResponse {
	return this.failSet(err.Error())
}

//解析授权后数据
func (this *AuthorizeResponse) analysisAuthQuery(query []byte) *AuthorizeResponse {
	array := strings.Split(string(query), "&")

	data := make(map[string]interface{}, 10)
	for _, v := range array {
		value := strings.Split(v, "=")
		data[value[0]] = value[1]
	}

	for k, v := range data {
		switch k {
		case "success":
			if value, ok := v.(string); ok {
				if "true" == value {
					this.success = true
				} else {
					this.success = false
				}
			}
		case "error_code":
			if value, ok := v.(string); ok {
				this.errorCode = value
			}
		case "error_message":
			if value, ok := v.(string); ok {
				//urlDecode转码
				val, _ := url.QueryUnescape(value)
				this.errorMessage = val
			}
		case "open_id":
			if value, ok := v.(string); ok {
				this.openId = value
			}
		case "app_id":
			if value, ok := v.(string); ok {
				this.appId = value
			}
		case "state":
			this.state = v
		default:
			continue
		}
	}
	return nil
}
