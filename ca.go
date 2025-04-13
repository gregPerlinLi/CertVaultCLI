package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"net/http"
	"os"
	"syscall"
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

		// BASE64解码逻辑
		decodedCert, decodeErr := base64.StdEncoding.DecodeString(cert)
		if decodeErr != nil {
			fmt.Printf("Error decoding certificate: %v\n", decodeErr)
			os.Exit(1)
		}

		// 新增输出逻辑
		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath == "" {
			fmt.Println(string(decodedCert))
		} else {
			err = writeToFile(outputPath, decodedCert)
			if err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Certificate saved to %s\n", outputPath)
		}
	},
}

// 新增获取CA私钥的命令定义
var getCAPrivateKeyCmd = &cobra.Command{
	Use:   "get-privkey [uuid]",
	Short: "Get CA private key (requires password verification)",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		uuid := args[0]
		password, _ := cmd.Flags().GetString("password")

		// 密码获取逻辑
		if password == "" {
			fmt.Print("Enter your password: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("Error reading password: %v\n", err)
				os.Exit(1)
			}
			password = string(bytePassword)
			fmt.Println() // 新增换行输出
		}

		privkey, err := client.GetCAPrivateKey(uuid, password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		// 解码显示私钥（假设返回的是base64编码）
		decodedBytes, err := base64.StdEncoding.DecodeString(privkey)
		if err != nil {
			fmt.Printf("Error decoding private key: %v\n", err)
			os.Exit(1)
		}

		// 新增输出逻辑
		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath == "" {
			fmt.Println(string(decodedBytes))
		} else {
			err = writeToFile(outputPath, decodedBytes)
			if err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key saved to %s\n", outputPath)
		}
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

// GetCAPrivateKey 新增获取CA私钥的方法
func (c *Client) GetCAPrivateKey(uuid string, password string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/admin/cert/ca/%s/privkey", c.BaseURL, uuid)
	data := map[string]string{
		"password": password,
	}
	body, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", fmt.Sprintf("JSESSIONID=%s", c.JSessionID))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data string `json:"data"`
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
	getCaCertCmd.Flags().StringP("output", "o", "",
		"Path to save certificate (default: print to stdout)")

	getCAPrivateKeyCmd.Flags().StringP("password", "p", "",
		"User password for private key verification")
	getCAPrivateKeyCmd.Flags().StringP("output", "o", "",
		"Path to save certificate (default: print to stdout)")

	caCmd.AddCommand(listCaCmd, getCaCertCmd, getCAPrivateKeyCmd)
}
