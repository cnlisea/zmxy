package authentication

/* 芝麻认证 */

import (
	"net/url"

	"github.com/cnlisea/zmxy/utils"
)

type AuthenticationZmApi struct {
	appId    string
	scene    string
	charset  string
	method   string //"zhima.auth.info.authquery"
	version  string
	channel  string //"api"
	platform string

	success bool   //whether success or failure
	errDesc string //error description
	url     string
}

func NewAuthentication(biz_no string, return_url string) *AuthenticationZmApi {
	authentication := &AuthenticationZmApi{
		appId:    utils.AppId,
		scene:    "apppc",
		charset:  "UTF-8",
		method:   "zhima.customer.certification.certify",
		version:  utils.APIVersion,
		channel:  "api",
		platform: "zmop",
	}
	return authentication.init(biz_no, return_url)
}

type authenticationResponse struct {
	Encrypted         bool        `json:"encrypted"`
	Biz_response      interface{} `json:"biz_response"`
	Biz_response_sign string      `json:"biz_response_sign,omitempty"`
}

type authenticationFailureData struct {
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code"`
	ErrorMes  string `json:"error_message"`
}

type authenticationSuccessData struct {
	Biz_no   string `json:"biz_no"`
	Zm_score string `json:"zm_score"`
}

func (this *AuthenticationZmApi) init(biz_no, return_url string) *AuthenticationZmApi {
	query := map[string]string{
		"app_id":   this.appId,
		"scene":    this.scene,
		"charset":  this.charset,
		"method":   this.method,
		"version":  this.version,
		"channel":  this.channel,
		"platform": this.platform,
	}

	//组织查询数据
	data := map[string]string{
		"biz_no":     biz_no,
		"return_url": return_url,
	}

	//data urlencode
	body := utils.BuildQuery(data)
	//data encrypt ==> RSA ==> encode
	bodyParams := utils.EncryptBase64(utils.EncryptRSA([]byte(body)))

	//create Sign
	query["sign"] = utils.Sign(body)

	//"https://zmopenapi.zmxy.com.cn/openapi.do"
	this.url = utils.GatewayUrl + "?" + utils.BuildQuery(query) + "&params=" + url.QueryEscape(bodyParams)
	this.success = true //成功标志
	return this
}

func (a *AuthenticationZmApi) failureSet(desc string) {
	a.success = false
	a.errDesc = desc
}

func (a *AuthenticationZmApi) UrlGet() string {
	return a.url
}

//是否成功
func (a *AuthenticationZmApi) IsSuccess() bool {
	return a.success
}

//失败原因
func (a *AuthenticationZmApi) ErrDesc() string {
	return a.errDesc
}
