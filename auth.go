package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/term" // 修改为标准库
	"net/http"
	"os"
	"syscall"
)

// 新增登录命令定义
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to CertVault",
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		// 新增交互式输入逻辑
		if username == "" || password == "" {
			if username == "" {
				fmt.Print("Username: ")
				fmt.Scanln(&username)
			}
			if password == "" {
				pwd, err := readPassword("Password: ")
				if err != nil {
					fmt.Printf("Error reading password: %v\n", err)
					os.Exit(1)
				}
				password = pwd
			}
		}

		err := client.Login(username, password)
		if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			os.Exit(1)
		}
		// 显示用户信息
		fmt.Printf("Logged in successfully. Session saved.\n")
		fmt.Printf("User: %s (%s)\n", client.User.Username, client.User.DisplayName)
		fmt.Printf("Email: %s\n", client.User.Email)
		fmt.Printf("Role: %d\n", client.User.Role)
	},
}

// Login 修改Client.Login方法确保正确处理用户数据
func (c *Client) Login(username, password string) error {
	url := c.BaseURL + "/api/v1/auth/login"
	data := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Network error during login: %v", err)
	}
	defer resp.Body.Close()

	// 新增：统一处理响应解析
	var result ResultVO
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("Failed to parse response: %v", err)
	}

	switch result.Code {
	case 200:
		// 确保用户数据解码成功
		var userProfile UserProfileDTO
		if err := json.Unmarshal(result.Data, &userProfile); err != nil {
			return fmt.Errorf("Failed to parse user data: %v", err)
		}
		c.User = &userProfile // 确保赋值给指针

		// 新增：处理JSESSIONID保存
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "JSESSIONID" {
				c.JSessionID = cookie.Value
				// 更新配置并保存（替换未定义的writeJSessionID函数）
				config, _ := readConfig()
				config.JSessionID = cookie.Value
				if err := writeConfig(config); err != nil {
					return fmt.Errorf("Failed to save session: %v", err)
				}
				return nil
			}
		}
		return fmt.Errorf("Login succeeded but JSESSIONID not found")
	default:
		return fmt.Errorf("Login failed: %s (code %d)", result.Msg, result.Code)
	}
}

// 修改密码读取函数实现
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin)) // 使用新包方法
	fmt.Println()                                              // 换行
	return string(bytePassword), err
}

func init() {
	// 设置登录命令参数
	loginCmd.Flags().StringP("username", "u", "", "Username")
	loginCmd.Flags().StringP("password", "p", "", "Password")

	// 将登录命令注册到根命令
	RootCmd.AddCommand(loginCmd)
}
