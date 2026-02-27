package cmd

import (
	"fmt"
	"os"

	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from CertVault",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := ui.WithSpinner("Logging out...", func() error {
			return client.Logout()
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Logout failed: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Logged out successfully!"))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
