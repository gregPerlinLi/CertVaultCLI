package cmd

import (
	"fmt"
	"os"

	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage application configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var setURLCmd = &cobra.Command{
	Use:   "set-url <url>",
	Short: "Set the API endpoint URL",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		newURL := args[0]
		if err := client.SetBaseURL(newURL); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to save configuration: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("API endpoint updated to " + newURL))
		return nil
	},
}

var getURLCmd = &cobra.Command{
	Use:   "get-url",
	Short: "Get the current API endpoint URL",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(ui.Label("API Endpoint", client.BaseURL()))
		return nil
	},
}

func init() {
	configCmd.AddCommand(setURLCmd, getURLCmd)
	rootCmd.AddCommand(configCmd)
}
