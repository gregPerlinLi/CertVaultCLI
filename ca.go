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
	"strings"
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
	Use:   "list [uuid]",
	Short: "List CA certificates or show details of a specific CA",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			uuid := args[0]
			caDetails, err := client.GetAdminCADetails(uuid)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			var caType string
			if caDetails.ParentCa == "" {
				caType = "Root CA"
			} else if !caDetails.AllowSubCa {
				caType = "Leaf CA"
			} else {
				caType = "Int CA"
			}
			fmt.Printf("UUID: %s\n", caDetails.UUID)
			fmt.Printf("Owner: %s\n", caDetails.Owner)
			fmt.Printf("Parent CA UUID: %s\n", caDetails.ParentCa)
			fmt.Printf("Type: %s\n", caType)
			fmt.Printf("Comment: %s\n", caDetails.Comment)
			fmt.Printf("Not Before: %s\n", caDetails.NotBefore)
			fmt.Printf("Not After: %s\n", caDetails.NotAfter)
			fmt.Printf("Available: %t\n", caDetails.Available)
		} else {
			keyword, _ := cmd.Flags().GetString("keyword")
			page, _ := cmd.Flags().GetInt("page")
			limit, _ := cmd.Flags().GetInt("limit")

			cas, err := client.ListAdminCAs(keyword, page, limit)
			if err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}

			// 新增表格边框定义
			sep := "+"
			widths := []int{38, 16, 38, 9, 41, 27, 7} // 增加 Comment 列宽度至40
			for _, w := range widths {
				sep += strings.Repeat("-", w) + "+"
			}
			fmt.Println(sep)

			// 打印表头
			fmt.Printf("| %-36s | %-14s | %-36s | %-7s | %-39s | %-25s | %-5s |\n", // 调整占位符宽度
				"UUID", "Owner", "Parent CA UUID", "Type", "Comment", "Expires", "Avail")
			fmt.Println(sep)

			for _, ca := range cas {
				var caType string
				if ca.ParentCa == "" {
					caType = "Root CA"
				} else if !ca.AllowSubCa {
					caType = "Leaf CA"
				} else {
					caType = "Int CA"
				}
				fmt.Printf("| %-36s | %-14s | %-36s | %-7s | %-39.39s | %-25s | %-5t |\n", // 增加Comment列截断长度
					ca.UUID, ca.Owner, ca.ParentCa, caType, ca.Comment, ca.NotAfter, ca.Available)
			}
			fmt.Println(sep)
		}
	},
}

// 新增分配CA列表命令定义
var listAllocatedCmd = &cobra.Command{
	Use:   "list-allocated [uuid]",
	Short: "List allocated CAs or show details of a specific CA",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			uuid := args[0]
			caDetails, err := client.GetAllocatedCADetails(uuid)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			var caType string
			if caDetails.ParentCa == "" {
				caType = "Root CA"
			} else if !caDetails.AllowSubCa {
				caType = "Leaf CA"
			} else {
				caType = "Int CA"
			}
			fmt.Printf("UUID: %s\n", caDetails.UUID)
			fmt.Printf("Owner: %s\n", caDetails.Owner)
			fmt.Printf("Parent CA UUID: %s\n", caDetails.ParentCa)
			fmt.Printf("Type: %s\n", caType)
			fmt.Printf("Comment: %s\n", caDetails.Comment)
			fmt.Printf("Not Before: %s\n", caDetails.NotBefore)
			fmt.Printf("Not After: %s\n", caDetails.NotAfter)
			fmt.Printf("Available: %t\n", caDetails.Available)
		} else {
			keyword, _ := cmd.Flags().GetString("keyword")
			page, _ := cmd.Flags().GetInt("page")
			limit, _ := cmd.Flags().GetInt("limit")

			cas, err := client.ListAllocatedCAs(keyword, page, limit)
			if err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}

			// 新增表格边框定义
			sep := "+"
			widths := []int{38, 16, 38, 9, 41, 27, 7} // 增加 Comment 列宽度至40
			for _, w := range widths {
				sep += strings.Repeat("-", w) + "+"
			}
			fmt.Println(sep)

			// 打印表头
			fmt.Printf("| %-36s | %-14s | %-36s | %-7s | %-39s | %-25s | %-5s |\n", // 调整占位符宽度
				"UUID", "Owner", "Parent CA UUID", "Type", "Comment", "Expires", "Avail")
			fmt.Println(sep)

			for _, ca := range cas {
				var caType string
				if ca.ParentCa == "" {
					caType = "Root CA"
				} else if !ca.AllowSubCa {
					caType = "Leaf CA"
				} else {
					caType = "Int CA"
				}
				fmt.Printf("| %-36s | %-14s | %-36s | %-7s | %-39.39s | %-25s | %-5t |\n", // 增加Comment列截断长度
					ca.UUID, ca.Owner, ca.ParentCa, caType, ca.Comment, ca.NotAfter, ca.Available)
			}
			fmt.Println(sep)
		}
	},
}

// 新增获取CA证书的子命令定义
var getCaCertCmd = &cobra.Command{
	Use:   "get-cert [uuid]",
	Short: "Get CA certificate content",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		uuid := args[0]
		isChain, _ := cmd.Flags().GetBool("is-chain")
		needRootCa, _ := cmd.Flags().GetBool("need-root-ca")
		analyze, _ := cmd.Flags().GetBool("analyze")

		cert, err := client.GetCACertificate(uuid, isChain, needRootCa)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		if analyze {
			analysis, err := client.AnalyzeCertificate(cert)
			if err != nil {
				fmt.Printf("Analysis failed: %v\n", err)
			} else {
				fmt.Printf("Certificate Analysis:\n")
				fmt.Printf("Subject: %s\n", analysis.Subject)
				fmt.Printf("Issuer: %s\n", analysis.Issuer)
				fmt.Printf("Not Before: %s\n", analysis.NotBefore)
				fmt.Printf("Not After: %s\n", analysis.NotAfter)
				fmt.Printf("Serial Number: %s\n", analysis.SerialNumber)
				fmt.Println("Public Key:")
				fmt.Printf("  Modulus: %s\n", analysis.PublicKey.Modulus)
				fmt.Printf("  Exponent: %s\n", analysis.PublicKey.Exponent)
				fmt.Printf("  Encoded: %s\n", analysis.PublicKey.Encoded)
				fmt.Printf("  Algorithm: %s\n", analysis.PublicKey.Algorithm)
				fmt.Printf("  Format: %s\n", analysis.PublicKey.Format)
				fmt.Printf("  Params: %s\n", analysis.PublicKey.Params)
				fmt.Println("Extensions:")
				for k, v := range analysis.Extensions {
					fmt.Printf("  %s: %s\n", k, v)
				}
			}
		} else {
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

// GetAdminCADetails 新增方法：获取CA详细信息
func (c *Client) GetAdminCADetails(uuid string) (*CaInfoDTO, error) {
	url := fmt.Sprintf("%s/api/v1/admin/cert/ca", c.BaseURL)
	params := fmt.Sprintf("?keyword=%s&limit=1", uuid)
	req, err := http.NewRequest("GET", url+params, nil)
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

	var pageDTO PageDTOCaInfoDTO
	err = json.Unmarshal(result.Data, &pageDTO)
	if err != nil {
		return nil, err
	}

	// 在列表中查找匹配的CA
	for _, ca := range pageDTO.List {
		if ca.UUID == uuid {
			return &ca, nil
		}
	}

	return nil, fmt.Errorf("Certificate not found")
}

// GetAllocatedCADetails 新增方法：获取分配到自己的CA详细信息
func (c *Client) GetAllocatedCADetails(uuid string) (*CaInfoDTO, error) {
	url := fmt.Sprintf("%s/api/v1/user/cert/ca", c.BaseURL)
	params := fmt.Sprintf("?keyword=%s&limit=1", uuid)
	req, err := http.NewRequest("GET", url+params, nil)
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

	var pageDTO PageDTOCaInfoDTO
	err = json.Unmarshal(result.Data, &pageDTO)
	if err != nil {
		return nil, err
	}

	// 在列表中查找匹配的CA
	for _, ca := range pageDTO.List {
		if ca.UUID == uuid {
			return &ca, nil
		}
	}

	return nil, fmt.Errorf("Certificate not found")
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

// ListAdminCAs 将现有ListCAs方法重命名为ListAdminCAs
func (c *Client) ListAdminCAs(keyword string, page int, limit int) ([]CaInfoDTO, error) {
	url := fmt.Sprintf("%s/api/v1/admin/cert/ca", c.BaseURL)
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

// ListAllocatedCAs 新增用户分配CA列表方法
func (c *Client) ListAllocatedCAs(keyword string, page int, limit int) ([]CaInfoDTO, error) {
	url := fmt.Sprintf("%s/api/v1/user/cert/ca", c.BaseURL)
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

	var pageDTO PageDTOCaInfoDTO
	err = json.Unmarshal(result.Data, &pageDTO)
	if err != nil {
		return nil, err
	}

	return pageDTO.List, nil
}

// 在init函数中注册新命令
func init() {
	listCaCmd.Flags().StringP("keyword", "k", "", "Search keyword (UUID/comment)")
	listCaCmd.Flags().IntP("page", "p", 1, "Page number")
	listCaCmd.Flags().IntP("limit", "l", 10, "Page limit (default 10)")

	listAllocatedCmd.Flags().StringP("keyword", "k", "", "Search keyword (UUID/comment)")
	listAllocatedCmd.Flags().IntP("page", "p", 1, "Page number")
	listAllocatedCmd.Flags().IntP("limit", "l", 10, "Page limit (default 10)")

	getCaCertCmd.Flags().Bool("is-chain", false, "Whether to get the certificate chain")
	getCaCertCmd.Flags().Bool("need-root-ca", true, "Whether to include root CA in chain")
	getCaCertCmd.Flags().BoolP("analyze", "a", false, "Analyze certificate details")
	getCaCertCmd.Flags().StringP("output", "o", "",
		"Path to save certificate (default: print to stdout)")

	getCAPrivateKeyCmd.Flags().StringP("password", "p", "",
		"User password for private key verification")
	getCAPrivateKeyCmd.Flags().StringP("output", "o", "",
		"Path to save certificate (default: print to stdout)")

	caCmd.AddCommand(listCaCmd, listAllocatedCmd, getCaCertCmd, getCAPrivateKeyCmd)
}
