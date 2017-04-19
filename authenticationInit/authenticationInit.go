package authenticationInit

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/astaxie/beego/httplib"
	"github.com/cnlisea/zmxy/utils"
)

/* 芝麻认证初始化 */

type AuthenticationInitZmApi struct {
	appId    string
	scene    string
	charset  string
	method   string //"zhima.customer.certification.initialize"
	version  string
	channel  string //"api"
	platform string

	success bool   //whether success or failure
	errDesc string //error description
	bizNo   string //init success
}

func NewAuthenticationInit(certName string, certNo string) *AuthenticationInitZmApi {
	authenticationInit := &AuthenticationInitZmApi{
		appId:    utils.AppId,
		scene:    "apppc",
		charset:  "UTF-8",
		method:   "zhima.customer.certification.initialize",
		version:  utils.APIVersion,
		channel:  "api",
		platform: "zmop",
	}
	return authenticationInit.init(authenticationInit.transactionGet(), "w1010100000000002978", certName, certNo)
}

type authenticationInitResponse struct {
	Encrypted         bool        `json:"encrypted"`
	Biz_response      interface{} `json:"biz_response"`
	Biz_response_sign string      `json:"biz_response_sign,omitempty"`
}

type authenticationInitFailureData struct {
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code"`
	ErrorMes  string `json:"error_message"`
}

type authenticationInitSuccessData struct {
	Biz_no   string `json:"biz_no"`
	Zm_score string `json:"zm_score"`
}

func (this *AuthenticationInitZmApi) init(transaction_id, product_code, certName, certNo string) *AuthenticationInitZmApi {
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
		"transaction_id": transaction_id,
		"product_code":   product_code,
		"biz_code":       "FACE",
		"identity_param": "{\"identity_type\":\"CERT_INFO\",\"cert_type\":\"IDENTITY_CARD\",\"cert_name\":\"" + certName + "\",\"cert_no\":\"" + certNo + "\"}",
		"ext_biz_param":  "{}",
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
	var res authenticationInitResponse
	if err := req.ToJSON(&res); nil != err {
		this.failureSet("return data cannot resolve")
		goto End
	}

	//判断是否失败
	if "" == res.Biz_response_sign {
		if data, ok := res.Biz_response.(string); ok {
			var errData authenticationInitFailureData
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

func (this *AuthenticationInitZmApi) analysisScoreQuery(query []byte) {
	var data authenticationInitSuccessData
	json.Unmarshal(query, &data)
	this.bizNo = data.Biz_no
	this.success = true
}

func (this *AuthenticationInitZmApi) BizNoGet() string {
	return this.bizNo
}
func (this *AuthenticationInitZmApi) failureSet(desc string) {
	this.success = false
	this.errDesc = desc
}

//是否成功
func (this *AuthenticationInitZmApi) IsSuccess() bool {
	return this.success
}

//失败原因
func (this *AuthenticationInitZmApi) ErrDesc() string {
	return this.errDesc
}

//生成业务号
//业务启始号
var g_number int64 = 1000000000000

//互斥锁
var g_mutex sync.Mutex

//创建订单号
func (this *AuthenticationInitZmApi) transactionGet() string {
	//by YYYYmmddHHMMSSsss format
	tran := time.Now().Format("20060102150405")
	g_mutex.Lock()
	g_number++
	tran = "cmbcs" + tran + strconv.FormatInt(g_number, 10)
	g_mutex.Unlock()
	return tran
}
