package cmd

import (
	"fmt"
	"os"

	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage user sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your login sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, _ := cmd.Flags().GetString("status")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		data, err := client.GetSessions(status, page, limit, "", false)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to fetch sessions: "+err.Error()))
			os.Exit(1)
		}

		t := ui.NewTable([]ui.TableColumn{
			{Title: "UUID", Width: 36},
			{Title: "IP Address", Width: 15},
			{Title: "Browser", Width: 20},
			{Title: "OS", Width: 15},
			{Title: "Login Time", Width: 25},
			{Title: "Online", Width: 6},
		})
		for _, s := range data.List {
			online := "No"
			if s.IsOnline {
				online = "Yes"
			}
			t.AddRow([]string{s.UUID, s.IPAddress, s.Browser, s.OS, s.LoginTime, online})
		}
		fmt.Printf("Total: %d sessions\n", data.Total)
		fmt.Println(t.Render())
		return nil
	},
}

var sessionLogoutCmd = &cobra.Command{
	Use:   "logout <uuid>",
	Short: "Force logout a specific session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		err := ui.WithSpinner("Logging out session...", func() error {
			return client.LogoutSession(uuid)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to logout session: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Session " + uuid + " logged out successfully!"))
		return nil
	},
}

var sessionLogoutAllCmd = &cobra.Command{
	Use:   "logout-all",
	Short: "Force logout all your sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		confirmed, err := ui.Confirm("Are you sure you want to logout all sessions?")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Println(ui.Info("Cancelled."))
			return nil
		}
		err = ui.WithSpinner("Logging out all sessions...", func() error {
			return client.LogoutAllSessions()
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to logout all sessions: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("All sessions logged out successfully!"))
		return nil
	},
}

func init() {
	sessionListCmd.Flags().String("status", "", "Filter by status (online/offline)")
	sessionListCmd.Flags().Int("page", 1, "Page number")
	sessionListCmd.Flags().Int("limit", 10, "Page size")
	sessionCmd.AddCommand(sessionListCmd, sessionLogoutCmd, sessionLogoutAllCmd)
	rootCmd.AddCommand(sessionCmd)
}
