// 新增config.go文件处理配置命令
package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage application configuration",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var setUrlCmd = &cobra.Command{
	Use:   "set-url [url]",
	Short: "Set the API endpoint URL",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		newURL := args[0]
		config, _ := readConfig()
		config.BaseURL = newURL
		err := writeConfig(config)
		if err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("API endpoint updated to %v\n", newURL)
	},
}

// 新增获取URL的子命令
var getUrlCmd = &cobra.Command{
	Use:   "get-url",
	Short: "Get the current API endpoint URL",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := readConfig()
		if err != nil {
			fmt.Printf("Error reading configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(config.BaseURL)
	},
}

func init() {
	configCmd.AddCommand(setUrlCmd, getUrlCmd) // 添加新命令
}
