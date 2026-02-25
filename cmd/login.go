package cmd

import (
	"fmt"
	"os"

	"github.com/gregPerlinLi/CertVaultCLI/internal/api"
	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to CertVault",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		var err error
		if username == "" {
			username, err = ui.ReadLine("Username: ")
			if err != nil {
				return err
			}
		}
		if password == "" {
			password, err = ui.ReadPassword("Password: ")
			if err != nil {
				return err
			}
		}

		var profile *api.UserProfileDTO
		err = ui.WithSpinner("Logging in...", func() error {
			profile, err = client.Login(username, password)
			return err
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Login failed: "+err.Error()))
			os.Exit(1)
		}

		fmt.Println(ui.Success("Logged in successfully!"))
		fmt.Println(ui.Label("Username", profile.Username))
		fmt.Println(ui.Label("Display Name", profile.DisplayName))
		fmt.Println(ui.Label("Email", profile.Email))
		fmt.Println(ui.Label("Role", profile.RoleName()))
		return nil
	},
}

func init() {
	loginCmd.Flags().StringP("username", "u", "", "Username")
	loginCmd.Flags().StringP("password", "p", "", "Password (not recommended; use interactive prompt instead)")
	rootCmd.AddCommand(loginCmd)
}
