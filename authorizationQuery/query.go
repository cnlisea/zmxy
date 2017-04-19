package authQuery

/* 芝麻信用授权查询 */

import (
	"encoding/json"

	"github.com/astaxie/beego/httplib"
	"github.com/cnlisea/zmxy/utils"
)

type AuthQueryZmApi struct {
	appId    string
	scene    string
	charset  string
	method   string //"zhima.auth.info.authquery"
	version  string
	channel  string //"api"
	platform string

	success    bool   //whether success or failure
	errDesc    string //error description
	authorized bool   //whether authorized or not authorize
}

//authorization query by open_id
func NewAuthQueryZmApiByOpenId(open_id string) *AuthQueryZmApi {
	authQuery := &AuthQueryZmApi{
		appId:    utils.AppId,
		scene:    "apppc",
		charset:  "UTF-8",
		method:   "zhima.auth.info.authquery",
		version:  utils.APIVersion,
		channel:  "api",
		platform: "zmop",
	}

	//organization query data
	data := map[string]string{
		"identity_type": "0",
	}
	param, _ := json.Marshal(map[string]string{
		"openId": open_id,
	})
	data["identity_param"] = string(param)

	return authQuery.init(data)
}

//authorization query by name and id_card
func NewAuthQueryZmApi(name string, id_card string) *AuthQueryZmApi {
	authQuery := &AuthQueryZmApi{
		appId:    utils.AppId,
		scene:    "apppc",
		charset:  "UTF-8",
		method:   "zhima.auth.info.authquery",
		version:  utils.APIVersion,
		channel:  "api",
		platform: "zmop",
	}
	//组织查询数据
	data := map[string]string{
		"identity_type": "2",
	}
	param, _ := json.Marshal(map[string]string{
		"certNo":   id_card,
		"certType": "IDENTITY_CARD",
		"name":     name,
	})
	data["identity_param"] = string(param)

	return authQuery.init(data)
}

type authQueryResponse struct {
	Encrypted         bool        `json:"encrypted"`
	Biz_response      interface{} `json:"biz_response"`
	Biz_response_sign string      `json:"biz_response_sign,omitempty"`
}

type authQuerySuccessData struct {
	Success    bool `json:"success"`
	Authorized bool `json:"authorized"`
}

type authQueryFailureData struct {
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code"`
	ErrorMes  string `json:"error_message"`
}

func (this *AuthQueryZmApi) init(data map[string]string) *AuthQueryZmApi {
	qeury := map[string]string{
		"app_id":   this.appId,
		"scene":    this.scene,
		"charset":  this.charset,
		"method":   this.method,
		"version":  this.version,
		"channel":  this.channel,
		"platform": this.platform,
	}

	//data urlencode
	body := utils.BuildQuery(data)
	//data encrypt ==> Base64(RSA)
	bodyParams := utils.EncryptBase64(utils.EncryptRSA([]byte(body)))
	//create Sign
	qeury["sign"] = utils.Sign(body)

	//set request
	//"https://zmopenapi.zmxy.com.cn/openapi.do"
	req := httplib.Post(utils.GatewayUrl + "?" + utils.BuildQuery(qeury))
	req.Param("params", bodyParams)

	//Analysis response data
	var res authQueryResponse
	if err := req.ToJSON(&res); nil != err {
		this.failureSet("return data cannot resolve")
		goto End
	}
	//判断是否失败
	if "" == res.Biz_response_sign {
		if data, ok := res.Biz_response.(string); ok {
			var errData authQueryFailureData
			json.Unmarshal([]byte(data), &errData)
			this.failureSet(errData.ErrorCode)
		}
	} else {
		if data, ok := res.Biz_response.(string); ok {
			decryptedQuery := utils.DecryptRSA(utils.DecryptBase64(data))
			this.analysisScoreQuery(decryptedQuery)
		}
	}
End:
	return this
}

func (this *AuthQueryZmApi) failureSet(desc string) {
	this.success = false
	this.errDesc = desc
}

func (this *AuthQueryZmApi) IsAuthorized() bool {
	return this.authorized
}

//是否成功
func (this *AuthQueryZmApi) IsSuccess() bool {
	return this.success
}

//失败原因
func (this *AuthQueryZmApi) ErrDesc() string {
	return this.errDesc
}

func (this *AuthQueryZmApi) analysisScoreQuery(query []byte) {
	var data authQuerySuccessData
	json.Unmarshal(query, &data)
	this.success = data.Success
	this.authorized = data.Authorized
}
