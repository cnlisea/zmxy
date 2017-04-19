package authenticationQuery

import (
	"encoding/json"

	"github.com/astaxie/beego/httplib"
	"github.com/cnlisea/zmxy/utils"
)

/* 芝麻认证查询 */

type AuthenticationQueryZmApi struct {
	appId    string
	scene    string
	charset  string
	method   string //"zhima.auth.info.authquery"
	version  string
	channel  string //"api"
	platform string

	success    bool   //whether success or failure
	errDesc    string //error description
	authStatus bool   // authentication status
}

func NewAuthenticationQuery(bizNo string) *AuthenticationQueryZmApi {
	authenticationQueryZmApi := &AuthenticationQueryZmApi{
		appId:    utils.AppId,
		scene:    "apppc",
		charset:  "UTF-8",
		method:   "zhima.customer.certification.query",
		version:  utils.APIVersion,
		channel:  "api",
		platform: "zmop",
	}
	return authenticationQueryZmApi.init(bizNo)
}

type authenticationQueryResponse struct {
	Encrypted         bool        `json:"encrypted"`
	Biz_response      interface{} `json:"biz_response"`
	Biz_response_sign string      `json:"biz_response_sign,omitempty"`
}

type authenticationQueryFailureData struct {
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code"`
	ErrorMes  string `json:"error_message"`
}

type authenticationQuerySuccessData struct {
	Passed           string `json:"passed"`
	Failed_reason    string `json:"failed_reason"`
	Channel_statuses string `json:"channel_statuses"`
}

func (this *AuthenticationQueryZmApi) init(bizNo string) *AuthenticationQueryZmApi {
	qeury := map[string]string{
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
		"biz_no": bizNo,
	}

	//data urlencode
	body := utils.BuildQuery(data)
	//data encrypt ==> Base64(RSA)
	bodyParams := utils.EncryptBase64(utils.EncryptRSA([]byte(body)))
	//create Sign
	qeury["sign"] = utils.Sign(body)

	//set request
	req := httplib.Post(utils.GatewayUrl + "?" + utils.BuildQuery(qeury))
	req.Param("params", bodyParams)

	//Analysis response data
	var res authenticationQueryResponse
	if err := req.ToJSON(&res); nil != err {
		this.failureSet("return data cannot resolve")
		goto End
	}

	//判断是否失败
	if "" == res.Biz_response_sign {
		if data, ok := res.Biz_response.(string); ok {
			var errData authenticationQueryFailureData
			json.Unmarshal([]byte(data), &errData)
			this.failureSet(errData.ErrorCode)
		}
	} else {
		if data, ok := res.Biz_response.(string); ok {
			decryptedQuery := utils.DecryptRSA(utils.DecryptBase64(data))
			this.analysisAuthQuery(decryptedQuery)
		}
	}

End:
	return this
}

func (this *AuthenticationQueryZmApi) analysisAuthQuery(query []byte) {
	var data authenticationQuerySuccessData
	json.Unmarshal(query, &data)
	if "true" == data.Passed {
		this.authStatus = true
	}
	this.success = true
}

func (this *AuthenticationQueryZmApi) failureSet(desc string) {
	this.success = false
	this.errDesc = desc
}

//认证状态
func (this *AuthenticationQueryZmApi) AuthStatus() bool {
	return this.authStatus
}

//是否成功
func (this *AuthenticationQueryZmApi) IsSuccess() bool {
	return this.success
}

//失败原因
func (this *AuthenticationQueryZmApi) ErrDesc() string {
	return this.errDesc
}
