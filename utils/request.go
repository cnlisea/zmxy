package utils

import (
	"crypto"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

var EncryptionFailed error = errors.New("encryption failed")

func BuildQuery(params map[string]string) string {
	array := make([]string, 0, len(params))
	for key, value := range params {
		if key == "" || value == "" {
			continue
		}
		array = append(array, key+"="+value)
	}
	return string(strings.Join(array, "&"))
}

func Encrypt(query string) (string, error) {
	return encryptQuery(query)
}

func encryptQuery(query string) (string, error) {
	encryptedQuery := EncryptBase64(EncryptRSA([]byte(query)))
	if "" == encryptedQuery {
		return "", EncryptionFailed
	}
	return url.QueryEscape(encryptedQuery), nil
}

func Sign(query string) string {
	return signQuery(query)
}

func signQuery(query string) string {
	signature := EncryptBase64(SignRSA([]byte(query), crypto.SHA1))
	return url.QueryEscape(signature)
}

func EncrytQuery(query string, appId string) (string, error) {
	encrypted := make([]string, 0)
	encrypted = append(encrypted, "params", "=")
	encryptedParams := EncryptBase64(EncryptRSA([]byte(query)))
	if "" == encryptedParams {
		return "", EncryptionFailed
	}
	encrypted = append(encrypted, url.QueryEscape(encryptedParams))
	encrypted = append(encrypted, "&", "appId", "=", appId)
	encrypted = append(encrypted, "&", "charset", "=", "UTF-8")
	encrypted = append(encrypted, "&", "sign", "=")
	signature := EncryptBase64(SignRSA([]byte(query), crypto.MD5))
	if "" == signature {
		return "", EncryptionFailed
	}
	encrypted = append(encrypted, url.QueryEscape(signature))
	encryptedQueryString := strings.Join(encrypted, "")
	return encryptedQueryString, nil
}

func HttpPost(client *http.Client, url string, content string, charset string) (string, error) {
	resp, err := client.Post(url, "application/x-www-form-urlencoded;charset="+charset, strings.NewReader(content))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
