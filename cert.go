package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"net/http"
	"os"
)

// 新增获取证书的子命令定义
var getCertCmd = &cobra.Command{
	Use:   "get-cert [uuid]",
	Short: "Get certificate content",
	Args:  cobra.MinimumNArgs(1), // 添加参数验证：必须包含一个位置参数
	Run: func(cmd *cobra.Command, args []string) {
		uuid := args[0]
		isChain, _ := cmd.Flags().GetBool("is-chain")
		needRootCa, _ := cmd.Flags().GetBool("need-root-ca")
		cert, err := client.GetCertificate(uuid, isChain, needRootCa)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		// BASE64解码逻辑
		decodedCert, decodeErr := base64.StdEncoding.DecodeString(cert)
		if decodeErr != nil {
			fmt.Printf("Error decoding certificate: %v\n", decodeErr)
			os.Exit(1)
		}

		fmt.Println(string(decodedCert))
	},
}

// ListCerts 将Certificate相关方法和命令移动到cert.go
func (c *Client) ListCerts(keyword string, page int, limit int) ([]CertificateInfoDTO, error) {
	url := fmt.Sprintf("%s/api/v1/user/cert/ssl", c.BaseURL)
	params := ""
	if keyword != "" {
		params += fmt.Sprintf("keyword=%s", keyword)
	}
	if page > 0 {
		params += fmt.Sprintf("&page=%d", page)
	}
	if limit > 0 {
		params += fmt.Sprintf("&limit=%d", limit)
	}
	if params != "" {
		url += "?" + params[1:] // 去除开头多余的&
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", fmt.Sprintf("JSESSIONID=%s", c.JSessionID))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ResultVO
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	if result.Code != 200 {
		return nil, fmt.Errorf("API error: %d - %s", result.Code, result.Msg)
	}

	var pageDTO PageDTOCertificateInfoDTO
	err = json.Unmarshal(result.Data, &pageDTO)
	if err != nil {
		return nil, err
	}

	return pageDTO.List, nil
}

func (c *Client) GetCertificate(uuid string, isChain bool, needRootCa bool) (string, error) {
	url := fmt.Sprintf("%s/api/v1/user/cert/ssl/%s/cer", c.BaseURL, uuid)
	params := ""
	if isChain {
		params += "isChain=true"
	}
	if !needRootCa {
		if params != "" {
			params += "&"
		}
		params += "needRootCa=false"
	}
	if params != "" {
		url += "?" + params
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	if c.JSessionID != "" {
		req.Header.Set("Cookie", fmt.Sprintf("JSESSIONID=%s", c.JSessionID))
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Code      int    `json:"code"`
		Msg       string `json:"msg"`
		Data      string `json:"data"`
		Timestamp string `json:"timestamp"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	if result.Code != 200 {
		return "", fmt.Errorf("API error: %d - %s", result.Code, result.Msg)
	}

	return result.Data, nil
}

// CertCmd 新增证书命令组
var CertCmd = &cobra.Command{
	Use:   "certs",
	Short: "Manage certificates",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// 列出证书命令
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List user certificates",
	Run: func(cmd *cobra.Command, args []string) {
		keyword, _ := cmd.Flags().GetString("keyword")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		certs, err := client.ListCerts(keyword, page, limit)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		for _, cert := range certs {
			fmt.Printf("UUID: %s\nComment: %s\nOwner: %s\nExpires: %s\n\n",
				cert.UUID, cert.Comment, cert.Owner, cert.NotAfter)
		}
	},
}

func init() {
	listCmd.Flags().StringP("keyword", "k", "", "Search keyword (UUID/comment)")
	listCmd.Flags().IntP("page", "p", 1, "Page number")
	listCmd.Flags().IntP("limit", "l", 10, "Page limit (default 10)")

	getCertCmd.Flags().Bool("is-chain", false, "Whether to get the certificate chain")
	getCertCmd.Flags().Bool("need-root-ca", true, "Whether to include root CA in chain")

	CertCmd.AddCommand(listCmd, getCertCmd)
}
