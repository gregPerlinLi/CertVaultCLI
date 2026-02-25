package cmd

import (
	"fmt"
	"os"

	"github.com/gregPerlinLi/CertVaultCLI/internal/api"
	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Show current user profile",
	RunE: func(cmd *cobra.Command, args []string) error {
		var profile *api.UserProfileDTO
		err := ui.WithSpinner("Fetching profile...", func() error {
			var e error
			profile, e = client.GetProfile()
			return e
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to fetch profile: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.TitleStyle.Render("User Profile"))
		fmt.Println(ui.Label("Username", profile.Username))
		fmt.Println(ui.Label("Display Name", profile.DisplayName))
		fmt.Println(ui.Label("Email", profile.Email))
		fmt.Println(ui.Label("Role", profile.RoleName()))
		return nil
	},
}

var profileUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update current user profile",
	RunE: func(cmd *cobra.Command, args []string) error {
		displayName, _ := cmd.Flags().GetString("display-name")
		email, _ := cmd.Flags().GetString("email")
		changePassword, _ := cmd.Flags().GetBool("password")

		dto := api.UpdateUserProfileDTO{
			DisplayName: displayName,
			Email:       email,
		}

		if changePassword {
			var err error
			dto.OldPassword, err = ui.ReadPassword("Current Password: ")
			if err != nil {
				return err
			}
			dto.NewPassword, err = ui.ReadPassword("New Password: ")
			if err != nil {
				return err
			}
		}

		err := ui.WithSpinner("Updating profile...", func() error {
			return client.UpdateProfile(dto)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to update profile: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Profile updated successfully!"))
		return nil
	},
}

func init() {
	profileUpdateCmd.Flags().String("display-name", "", "New display name")
	profileUpdateCmd.Flags().String("email", "", "New email address")
	profileUpdateCmd.Flags().Bool("password", false, "Change password (interactive)")
	profileCmd.AddCommand(profileUpdateCmd)
	rootCmd.AddCommand(profileCmd)
}
