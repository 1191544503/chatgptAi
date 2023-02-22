package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sbzhu/weworkapi_golang/wxbizmsgcrypt"
	"gopkg.in/yaml.v2"
)

const (
	webhookURL = "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s"
	chatGPTAPI = "https://api.openai.com/v1/completions"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	ErrorCode   int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

type AccessToken struct {
	Token     string
	ExpiresAt time.Time
}

type AccessTokenManager struct {
	corpID     string
	corpSecret string
	mutex      sync.RWMutex
	token      AccessToken
}

type WxPushMessage struct {
	Touser   string          `json:"touser"`
	Msgtype  string          `json:"msgtype"`
	Agentid  int             `json:"agentid"`
	Markdown MarkdownMessage `json:"markdown"`
	Safe     int             `json:"safe"`
}

type MarkdownMessage struct {
	Content string `json:"content"`
}

type MsgContent struct {
	ToUsername   string `xml:"ToUserName"`
	FromUsername string `xml:"FromUserName"`
	CreateTime   int64  `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	Content      string `xml:"Content"`
	Msgid        string `xml:"MsgId"`
	Agentid      uint32 `xml:"AgentId"`
}

type ChatGPTResponse struct {
	Choices []struct {
		Text string `json:"text"`
	} `json:"choices"`
}

type WeChatMessage struct {
	ToUserName   string `xml:"ToUserName"`
	FromUserName string `xml:"FromUserName"`
	CreateTime   int64  `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	Content      string `xml:"Content"`
	MsgId        int64  `xml:"MsgId"`
}

type Config struct {
	OpenAI struct {
		APIKey    string `yaml:"openaiAPIKey"`
		MaxTokens int    `yaml:"maxTokens"`
		Model     string `yaml:"model"`
	} `yaml:"OpenAI"`
	WeChat struct {
		Token          string `yaml:"token"`
		EncodingAESKey string `yaml:"encodingAESKey"`
		ReceiverId     string `yaml:"receiverId"`
		CorpID         string `yaml:"corpid"`
		CorpSecret     string `yaml:"corpsecret"`
	} `yaml:"WeChat"`
}

var manager *AccessTokenManager
var config *Config

func main() {
	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		fmt.Println("Failed to read the YAML file:", err)
	}

	// 解析 YAML
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		fmt.Println("Failed to parse the YAML file:", err)
	}

	manager = NewAccessTokenManager(config.WeChat.CorpID, config.WeChat.CorpSecret)
	http.HandleFunc("/chatgpt", handleRequest)
	http.ListenAndServe(":8080", nil)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	reqMsgSign := r.URL.Query().Get("msg_signature")
	reqTimestamp := r.URL.Query().Get("timestamp")
	reqNonce := r.URL.Query().Get("nonce")
	reqData, err := ioutil.ReadAll(r.Body)
	//	echoStr := r.URL.Query().Get("echostr")
	fmt.Println("params reqMsgSign", reqMsgSign)
	fmt.Println("params reqNonce", reqNonce)
	fmt.Println("params reqTimestamp", reqTimestamp)
	fmt.Println("params reqData", reqData)

	wxcpt := wxbizmsgcrypt.NewWXBizMsgCrypt(config.WeChat.Token, config.WeChat.EncodingAESKey, config.WeChat.ReceiverId, wxbizmsgcrypt.XmlType)
	// echoStr1, cryptErr := wxcpt.VerifyURL(reqMsgSign, reqTimestamp, reqNonce, echoStr)
	// if nil != cryptErr {
	// 	fmt.Println("VerifyURL fail", cryptErr)
	// }

	//	fmt.Fprint(w, string(echoStr1))

	msg, cryptErr := wxcpt.DecryptMsg(reqMsgSign, reqTimestamp, reqNonce, reqData)
	if nil != cryptErr {
		fmt.Println("DecryptMsg fail", cryptErr)
	}

	var msgContent MsgContent
	err = xml.Unmarshal(msg, &msgContent)
	if nil != err {
		fmt.Println("Unmarshal fail")
	} else {
		fmt.Println("decrypt struct", msgContent)
	}

	if msgContent.MsgType != "text" {
		http.Error(w, "Unsupported message type", http.StatusBadRequest)
		return
	}

	go handleCore(msgContent)
	reply := WeChatMessage{
		ToUserName:   msgContent.FromUsername,
		FromUserName: msgContent.ToUsername,
		CreateTime:   msgContent.CreateTime,
		MsgType:      "text",
		Content:      "",
	}
	xmlData, err := xml.Marshal(reply)
	if err != nil {
		fmt.Println("xmlMarshal fail", reply)
		return
	}

	encryptMsg, cryptErr := wxcpt.EncryptMsg(string(xmlData), reqTimestamp, reqNonce)
	if nil != cryptErr {
		fmt.Println("EncryptMsg fail", cryptErr)
	}

	sEncryptMsg := string(encryptMsg)
	fmt.Println("response", sEncryptMsg)
	fmt.Fprint(w, string(""))
}

func handleCore(msgContent MsgContent) {
	response, err := getChatGPTResponse(msgContent.Content)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("chatgpt text:", response)
	// err = sendWeChatMessage(response, msgContent.FromUsername)
	// if err != nil {
	// 	return
	// }
	sendMessageWithSegment(response, msgContent.FromUsername)
}

func sendMessageWithSegment(message string, tousername string) {
	// 按行分割代码
	codeLines := strings.Split(message, "\n")

	// 将每行代码拼接为一个完整消息
	var fullMessage string
	for _, line := range codeLines {
		fullMessage += line + "\n"
		// 如果拼接后的消息长度超过2000，则发送前一个消息并清空fullMessage
		if len(fullMessage) > 2000 {
			sendWeChatMessage(fullMessage, tousername)
			fullMessage = ""
		}
	}
	// 发送最后一个消息
	if fullMessage != "" {
		sendWeChatMessage(fullMessage, tousername)
	}
}

func extractMessage(body []byte) (*WeChatMessage, error) {
	var message WeChatMessage
	err := json.Unmarshal(body, &message)
	if err != nil {
		return nil, err
	}
	return &message, nil
}

func getChatGPTResponse(prompt string) (string, error) {
	data := struct {
		Prompt    string `json:"prompt"`
		MaxTokens int    `json:"max_tokens"`
		Model     string `json:"model"`
	}{
		prompt,
		config.OpenAI.MaxTokens,
		config.OpenAI.Model,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, chatGPTAPI, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.OpenAI.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	data2 := make(map[string]interface{})
	d := json.NewDecoder(bytes.NewReader(respBody))
	d.UseNumber()
	_ = d.Decode(&data2)
	fmt.Println("chatgpt response:", data2)
	if data2["error"] != nil {
		return "server error,please retry", nil
	}

	var respData ChatGPTResponse
	err = json.Unmarshal(respBody, &respData)
	if err != nil {
		return "", err
	}

	if len(respData.Choices) == 0 {
		return "", fmt.Errorf("No response from ChatGPT")
	}

	return strings.TrimSpace(respData.Choices[0].Text), nil
}

func sendWeChatMessage(message string, tousername string) error {
	accessToken, err := manager.GetToken()
	if err != nil {
		fmt.Println("get accessToken err", err)
	}
	fmt.Println("now accessToken:", accessToken)
	postUrl := fmt.Sprintf(webhookURL, accessToken)
	Markdowndata := MarkdownMessage{
		Content: message,
	}

	reply := WxPushMessage{
		Touser:   tousername,
		Msgtype:  "markdown",
		Agentid:  1000002,
		Markdown: Markdowndata,
		Safe:     0,
	}
	jsonStr, _ := json.Marshal(reply)
	fmt.Println("send wechat request", reply)
	req, err := http.NewRequest(http.MethodPost, postUrl, bytes.NewBuffer(jsonStr))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	data2 := make(map[string]interface{})
	d := json.NewDecoder(bytes.NewReader(respBody))
	d.UseNumber()
	_ = d.Decode(&data2)
	fmt.Println("wx response:", data2)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to send message to WeChat: %d", resp.StatusCode)
	}

	return nil
}

func NewAccessTokenManager(corpID, corpSecret string) *AccessTokenManager {
	return &AccessTokenManager{
		corpID:     corpID,
		corpSecret: corpSecret,
	}
}

func (m *AccessTokenManager) GetToken() (string, error) {
	m.mutex.RLock()
	if m.token.Token != "" && time.Now().Before(m.token.ExpiresAt) {
		defer m.mutex.RUnlock()
		return m.token.Token, nil
	}
	m.mutex.RUnlock()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	token, err := m.getAccessToken()
	if err != nil {
		return "", err
	}

	m.token.Token = token
	m.token.ExpiresAt = time.Now().Add(time.Duration(1) * time.Hour) // Access token expires in 1 hour

	return token, nil
}

func (m *AccessTokenManager) getAccessToken() (string, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s", m.corpID, m.corpSecret)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tokenResp AccessTokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", err
	}

	if tokenResp.ErrorCode != 0 {
		return "", fmt.Errorf("failed to get access_token: %s", tokenResp.ErrMsg)
	}

	return tokenResp.AccessToken, nil
}
