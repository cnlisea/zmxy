package scoreQuery

//ZhimaCredit score query

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/astaxie/beego/httplib"
	"github.com/cnlisea/zmxy/utils"
)

type ScoreZmApi struct {
	appId    string
	scene    string
	charset  string
	method   string //"zhima.credit.score.get"
	version  string
	channel  string //"api"
	platform string

	success  bool   //whether success or failure
	errDesc  string //error description
	bizNo    string //Service number
	zm_score string //zhima score
}

func NewScoreZmApi(open_id string) *ScoreZmApi {
	score := &ScoreZmApi{
		appId:    utils.AppId,
		scene:    "apppc",
		charset:  "UTF-8",
		method:   "zhima.credit.score.get",
		version:  utils.APIVersion,
		channel:  "api",
		platform: "zmop",
	}

	return score.init(score.transactionGet(), "w1010100100000000001", open_id)
}

type scoreResponse struct {
	Encrypted         bool        `json:"encrypted"`
	Biz_response      interface{} `json:"biz_response"`
	Biz_response_sign string      `json:"biz_response_sign,omitempty"`
}

type scoreSuccessData struct {
	Biz_no   string `json:"biz_no"`
	Zm_score string `json:"zm_score"`
}

type scoreFailureData struct {
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code"`
	ErrorMes  string `json:"error_message"`
}

func (this *ScoreZmApi) init(transaction_id, product_code, open_id string) *ScoreZmApi {
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
		"open_id":        open_id,
	}

	//data urlencode
	body := utils.BuildQuery(data)
	//data encrypt ==> Base64(RSA)
	bodyParams := utils.EncryptBase64(utils.EncryptRSA([]byte(body)))
	//create Sign
	qeury["sign"] = utils.Sign(body)

	//"https://zmopenapi.zmxy.com.cn/openapi.do"
	//set request
	req := httplib.Post(utils.GatewayUrl + "?" + utils.BuildQuery(qeury))
	req.Param("params", bodyParams)

	//Analysis response data
	var res scoreResponse
	if err := req.ToJSON(&res); nil != err {
		this.failureSet("return data cannot resolve")
		goto End
	}

	//判断是否失败
	if "" == res.Biz_response_sign {
		if data, ok := res.Biz_response.(string); ok {
			var errData scoreFailureData
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

func (this *ScoreZmApi) failureSet(desc string) {
	this.success = false
	this.errDesc = desc
}

//获取芝麻分
func (this *ScoreZmApi) ScoreGet() string {
	return this.zm_score
}

//是否成功
func (this *ScoreZmApi) IsSuccess() bool {
	return this.success
}

//失败原因
func (this *ScoreZmApi) ErrDesc() string {
	return this.errDesc
}

//获取业务号
func (this *ScoreZmApi) BzNoGet() string {
	return this.bizNo
}

//解析查询芝麻分数据
func (this *ScoreZmApi) analysisScoreQuery(query []byte) {
	var data scoreSuccessData
	json.Unmarshal(query, &data)
	this.bizNo = data.Biz_no
	this.zm_score = data.Zm_score
	this.success = true
}

//生成业务号
//业务启始号
var g_number int64 = 1000000000000

//互斥锁
var g_mutex sync.Mutex

//创建订单号
func (this *ScoreZmApi) transactionGet() string {
	//by YYYYmmddHHMMSSsss format
	tran := time.Now().Format("20060102150405.000")
	tran = strings.Replace(tran, ".", "", 1)
	g_mutex.Lock()
	g_number++
	tran = tran + strconv.FormatInt(g_number, 10)
	g_mutex.Unlock()
	return tran
}
