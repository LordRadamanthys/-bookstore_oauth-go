package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LordRadamanthys/-bookstore_oauth-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   string `json:"user_id"`
	ClientId string `json:"client_id"`
}

type oauthInterface interface {
}

func GetCallerId(request *http.Request) int {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 0)
	if err != nil {
		return 0
	}

	return int(callerId)
}

func GetClientId(request *http.Request) int {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 0)
	if err != nil {
		return 0
	}

	return int(clientId)
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"

}

func AuthenticateRequest(request *http.Request) *errors.RestErr {

	if request == nil {
		return nil
	}
	cleanRequest(request)
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))

	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)

	if err != nil {
		return err
	}
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXCallerId)
	request.Header.Del(headerXClientId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	path := fmt.Sprintf("/oauth/access_token/%s", accessTokenId)
	response := oauthRestClient.Get(path)

	if response == nil || response.Response == nil {
		return nil, errors.InternalServerError("invalid rest client response when trying to login user")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.InternalServerError("invalid error interface")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.InternalServerError("error trying to parse rest response")
	}

	return &at, nil
}
