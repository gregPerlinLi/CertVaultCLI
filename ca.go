package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"net/http"
	"os"
)

// 新增caCmd命令组定义
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage CA certificates",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// 新增CA列表命令定义
var listCaCmd = &cobra.Command{
	Use:   "list",
	Short: "List CA certificates",
	Run: func(cmd *cobra.Command, args []string) {
		keyword, _ := cmd.Flags().GetString("keyword")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		cas, err := client.ListCAs(keyword, page, limit)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		for _, ca := range cas {
			var caType string
			if ca.ParentCa == "" {
				caType = "Root CA"
			} else if !ca.AllowSubCa {
				caType = "Leaf CA"
			} else {
				caType = "Intermediate CA"
			}
			fmt.Printf("UUID: %s\nOwner: %s\nParent CA UUID: %s\nType: %s\nComment: %s\nExpires: %s\nAvailable: %t\n\n",
				ca.UUID, ca.Owner, ca.ParentCa, caType, ca.Comment, ca.NotAfter, ca.Available)
		}
	},
}

// 新增获取CA证书的子命令定义
var getCaCertCmd = &cobra.Command{
	Use:   "get-cert [uuid]",
	Short: "Get CA certificate content",
	Args:  cobra.MinimumNArgs(1), // 添加参数验证：必须包含一个位置参数
	Run: func(cmd *cobra.Command, args []string) {
		uuid := args[0]
		isChain, _ := cmd.Flags().GetBool("is-chain")
		needRootCa, _ := cmd.Flags().GetBool("need-root-ca")
		cert, err := client.GetCACertificate(uuid, isChain, needRootCa)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		// 新增BASE64解码逻辑
		decodedCert, decodeErr := base64.StdEncoding.DecodeString(cert)
		if decodeErr != nil {
			fmt.Printf("Error decoding certificate: %v\n", decodeErr)
			os.Exit(1)
		}

		fmt.Println(string(decodedCert))
	},
}

type CaInfoDTO struct {
	UUID       string `json:"uuid"`
	Owner      string `json:"owner"`
	AllowSubCa bool   `json:"allowSubCa"`
	Comment    string `json:"comment"`
	Available  bool   `json:"available"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
	ParentCa   string `json:"parentCa"` // 新增字段：存储母CA UUID
}

func (c *Client) ListCAs(keyword string, page int, limit int) ([]CaInfoDTO, error) {
	url := fmt.Sprintf("%s/api/v1/admin/cert/ca", c.BaseURL)
	params := ""
	if keyword != "" {
		params += fmt.Sprintf("keyword=%s", keyword)
	}
	if page > 0 {
		if params != "" {
			params += "&"
		}
		params += fmt.Sprintf("page=%d", page)
	}
	if limit > 0 {
		if params != "" {
			params += "&"
		}
		params += fmt.Sprintf("limit=%d", limit)
	}
	if params != "" {
		url += "?" + params
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.JSessionID != "" {
		req.Header.Set("Cookie", fmt.Sprintf("JSESSIONID=%s", c.JSessionID))
	}

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

	var pageDTO PageDTOCaInfoDTO
	err = json.Unmarshal(result.Data, &pageDTO)
	if err != nil {
		return nil, err
	}

	return pageDTO.List, nil
}

// GetCACertificate 新增方法：获取CA证书内容
func (c *Client) GetCACertificate(uuid string, isChain bool, needRootCa bool) (string, error) {
	url := fmt.Sprintf("%s/api/v1/user/cert/ca/%s/cer", c.BaseURL, uuid)
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

	// 添加认证头
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

type PageDTOCaInfoDTO struct {
	Total int64       `json:"total"`
	List  []CaInfoDTO `json:"list"`
}

func init() {
	listCaCmd.Flags().StringP("keyword", "k", "", "Search keyword (UUID/comment)")
	listCaCmd.Flags().IntP("page", "p", 1, "Page number")
	listCaCmd.Flags().IntP("limit", "l", 10, "Page limit (default 10)")

	getCaCertCmd.Flags().Bool("is-chain", false, "Whether to get the certificate chain")
	getCaCertCmd.Flags().Bool("need-root-ca", true, "Whether to include root CA in chain")

	caCmd.AddCommand(listCaCmd, getCaCertCmd)
}
