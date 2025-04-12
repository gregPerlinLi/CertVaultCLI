package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage user sessions",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var listSessionsCmd = &cobra.Command{
	Use:   "list",
	Short: "List user sessions",
	Run: func(cmd *cobra.Command, args []string) {
		// 实现会话列表逻辑（参考docs.yaml中的/api/v1/user/session接口）
		// 需要添加对应的结构体和API调用方法
		fmt.Println("Session list not implemented yet")
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Force logout all sessions",
	Run: func(cmd *cobra.Command, args []string) {
		// 实现强制登出逻辑（参考docs.yaml中的/api/v1/user/logout接口）
		fmt.Println("Logout not implemented yet")
	},
}

func init() {
	sessionCmd.AddCommand(listSessionsCmd, logoutCmd)
	RootCmd.AddCommand(sessionCmd)
}
