package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
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
		analyze, _ := cmd.Flags().GetBool("analyze") // 新增分析标志

		cert, err := client.GetSSLCertificate(uuid, isChain, needRootCa)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		if analyze { // 新增分析逻辑
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
			// BASE64解码并输出原有逻辑
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
var getPrivateKeyCmd = &cobra.Command{
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

		privkey, err := client.GetSSLPrivateKey(uuid, password)
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

func (c *Client) GetSSLCertificate(uuid string, isChain bool, needRootCa bool) (string, error) {
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

// GetSSLPrivateKey 新增获取SSL私钥的方法
func (c *Client) GetSSLPrivateKey(uuid string, password string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/user/cert/ssl/%s/privkey", c.BaseURL, uuid)
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

// CertCmd 新增证书命令组
var CertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage certificates",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// 列出证书命令
var listCmd = &cobra.Command{
	Use:   "list [uuid]",
	Short: "List user certificates or show details of a specific certificate",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			uuid := args[0]
			certDetails, err := client.GetSSLCertificateDetails(uuid)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("UUID: %s\n", certDetails.UUID)
			fmt.Printf("Comment: %s\n", certDetails.Comment)
			fmt.Printf("Owner: %s\n", certDetails.Owner)
			fmt.Printf("Not Before: %s\n", certDetails.NotBefore)
			fmt.Printf("Not After: %s\n", certDetails.NotAfter)
			fmt.Printf("Cert: %s\n", certDetails.Cert)
			fmt.Printf("CA UUID: %s\n", certDetails.CaUuid)
			fmt.Printf("Created At: %s\n", certDetails.CreatedAt)
			fmt.Printf("Modified At: %s\n", certDetails.ModifiedAt)
		} else {
			keyword, _ := cmd.Flags().GetString("keyword")
			page, _ := cmd.Flags().GetInt("page")
			limit, _ := cmd.Flags().GetInt("limit")

			certs, err := client.ListCerts(keyword, page, limit)
			if err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}

			// 新增表格边框定义
			sep := "+"
			widths := []int{38, 41, 16, 27} // 增加 Comment 列宽度至35
			for _, w := range widths {
				sep += strings.Repeat("-", w) + "+"
			}
			fmt.Println(sep)

			// 打印表头
			fmt.Printf("| %-36s | %-39s | %-14s | %-25s |\n", // 调整占位符宽度
				"UUID", "Comment", "Owner", "Expires")
			fmt.Println(sep)

			for _, cert := range certs {
				fmt.Printf("| %-36s | %-39.39s | %-14s | %-25s |\n", // 增加Comment列截断长度
					cert.UUID, cert.Comment, cert.Owner, cert.NotAfter)
			}
			fmt.Println(sep)
		}
	},
}

// 新增证书分析命令定义
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze PEM certificate content",
	Run: func(cmd *cobra.Command, args []string) {
		filePath, _ := cmd.Flags().GetString("file")

		var certPEM []byte
		var err error

		if filePath != "" {
			certPEM, err = os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				os.Exit(1)
			}
		} else {
			certPEM, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Printf("Error reading stdin: %v\n", err)
				os.Exit(1)
			}
		}

		// 转换为BASE64字符串
		certBase64 := base64.StdEncoding.EncodeToString(certPEM)

		analysis, err := client.AnalyzeCertificate(certBase64)
		if err != nil {
			fmt.Printf("Analysis failed: %v\n", err)
			os.Exit(1)
		}

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
	},
}

func init() {
	listCmd.Flags().StringP("keyword", "k", "", "Search keyword (UUID/comment)")
	listCmd.Flags().IntP("page", "p", 1, "Page number")
	listCmd.Flags().IntP("limit", "l", 10, "Page limit (default 10)")

	getCertCmd.Flags().Bool("is-chain", false, "Whether to get the certificate chain")
	getCertCmd.Flags().Bool("need-root-ca", true, "Whether to include root CA in chain")
	getCertCmd.Flags().StringP("output", "o", "",
		"Path to save certificate (default: print to stdout)")
	getCertCmd.Flags().BoolP("analyze", "a", false, "Analyze certificate details")

	getPrivateKeyCmd.Flags().StringP("password", "p", "",
		"User password for private key verification")
	getPrivateKeyCmd.Flags().StringP("output", "o", "",
		"Path to save certificate (default: print to stdout)")

	analyzeCmd.Flags().StringP("file", "f", "",
		"Path to PEM certificate file (default: read from stdin)")

	CertCmd.AddCommand(listCmd, getCertCmd, getPrivateKeyCmd, analyzeCmd)
}

// AnalyzeCertificate 新增分析方法到Client结构体
func (c *Client) AnalyzeCertificate(cert string) (*CertificateAnalysisDTO, error) {
	url := c.BaseURL + "/api/v1/user/cert/analyze"
	data := map[string]string{
		"cert": cert,
	}
	body, _ := json.Marshal(data)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", fmt.Sprintf("JSESSIONID=%s", c.JSessionID))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Code      int                    `json:"code"`
		Msg       string                 `json:"msg"`
		Data      CertificateAnalysisDTO `json:"data"`
		Timestamp string                 `json:"timestamp"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	if result.Code != 200 {
		return nil, fmt.Errorf("Analysis failed: %d - %s", result.Code, result.Msg)
	}

	return &result.Data, nil
}

type CertificateAnalysisDTO struct {
	Subject      string            `json:"subject"`
	Issuer       string            `json:"issuer"`
	NotBefore    string            `json:"notBefore"`
	NotAfter     string            `json:"notAfter"`
	SerialNumber string            `json:"serialNumber"`
	PublicKey    PublicKey         `json:"publicKey"`
	Extensions   map[string]string `json:"extensions"`
}

type PublicKey struct {
	Modulus   string `json:"modulus"`
	Exponent  string `json:"publicExponent"`
	Encoded   string `json:"encoded"`
	Algorithm string `json:"algorithm"`
	Format    string `json:"format"`
	Params    string `json:"params"`
}

// 新增 GetSSLCertificateDetails 方法到 Client
func (c *Client) GetSSLCertificateDetails(uuid string) (*CertificateInfoDTO, error) {
	url := fmt.Sprintf("%s/api/v1/user/cert/ssl", c.BaseURL)
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

	var pageDTO PageDTOCertificateInfoDTO
	err = json.Unmarshal(result.Data, &pageDTO)
	if err != nil {
		return nil, err
	}

	// 在列表中查找匹配的证书
	for _, cert := range pageDTO.List {
		if cert.UUID == uuid {
			return &cert, nil
		}
	}

	return nil, fmt.Errorf("Certificate not found")
}
