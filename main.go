package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net/http"
	"os"
)

type ResultVO struct {
	Code      int             `json:"code"`
	Msg       string          `json:"msg"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
}

type CertificateInfoDTO struct {
	UUID       string `json:"uuid"`
	CaUuid     string `json:"caUuid"`
	Owner      string `json:"owner"`
	Comment    string `json:"comment"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
	CreatedAt  string `json:"createdAt"`
	ModifiedAt string `json:"modifiedAt"`
	Cert       string `json:"cert"`
}

type PageDTOCertificateInfoDTO struct {
	Total int64                `json:"total"`
	List  []CertificateInfoDTO `json:"list"`
}

type UserProfileDTO struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Role        int32  `json:"role"`
}

type Client struct {
	BaseURL    string
	JSessionID string
	User       *UserProfileDTO
	HTTPClient *http.Client
}

// 修改配置结构包含JSESSIONID
type Config struct {
	BaseURL    string `json:"baseURL"`
	JSessionID string `json:"jSessionID"`
}

// 替换原有配置读取函数
func readConfig() (*Config, error) {
	data, err := ioutil.ReadFile(".cv-config")
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{
				BaseURL: "http://127.0.0.1:1888",
			}, nil
		}
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// 替换原有配置写入函数
func writeConfig(config *Config) error {
	data, _ := json.MarshalIndent(config, "", "  ")
	return ioutil.WriteFile(".cv-config", data, 0644)
}

// 修改Client初始化逻辑
func NewClient() *Client {
	config, err := readConfig()
	if err != nil {
		config = &Config{
			BaseURL: "http://127.0.0.1:1888",
		}
	}
	client := &Client{
		BaseURL:    config.BaseURL,
		JSessionID: config.JSessionID,
		HTTPClient: &http.Client{},
	}
	return client
}

var RootCmd = &cobra.Command{
	Use:   "cv",
	Short: "CertVault CLI client",
}

// 新增全局Client变量
var client *Client

// 修改init函数初始化全局Client
func init() {
	RootCmd.AddCommand(configCmd)
	RootCmd.AddCommand(CertCmd)
	RootCmd.AddCommand(caCmd)
	client = NewClient()
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
