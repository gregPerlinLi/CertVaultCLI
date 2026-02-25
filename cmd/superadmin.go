package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/gregPerlinLi/CertVaultCLI/internal/api"
	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var superadminCmd = &cobra.Command{
	Use:   "superadmin",
	Short: "Superadmin-only commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var superadminSessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List all login sessions (superadmin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, _ := cmd.Flags().GetString("status")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")
		data, err := client.SuperAdminListAllSessions(status, page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		printSessionTable(data.List, data.Total)
		return nil
	},
}

var superadminUserSessionsCmd = &cobra.Command{
	Use:   "user-sessions <username>",
	Short: "List a user's login sessions (superadmin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		status, _ := cmd.Flags().GetString("status")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")
		data, err := client.SuperAdminGetUserSessions(args[0], status, page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		printSessionTable(data.List, data.Total)
		return nil
	},
}

var superadminForceLogoutCmd = &cobra.Command{
	Use:   "force-logout <username>",
	Short: "Force logout a user (superadmin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := client.SuperAdminForceLogoutUser(args[0]); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("User " + args[0] + " has been logged out!"))
		return nil
	},
}

var superadminCreateUserCmd = &cobra.Command{
	Use:   "create-user",
	Short: "Create a new user (superadmin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dto := api.CreateUserDTO{}
		dto.Username, _ = cmd.Flags().GetString("username")
		dto.DisplayName, _ = cmd.Flags().GetString("display-name")
		dto.Email, _ = cmd.Flags().GetString("email")
		dto.Password, _ = cmd.Flags().GetString("password")
		roleStr, _ := cmd.Flags().GetString("role")
		role, err := parseRole(roleStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		dto.Role = role

		if dto.Password == "" {
			dto.Password, err = ui.ReadPassword("Password for new user: ")
			if err != nil {
				return err
			}
		}

		if err := client.SuperAdminCreateUser(dto); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("User " + dto.Username + " created!"))
		return nil
	},
}

var superadminUpdateUserCmd = &cobra.Command{
	Use:   "update-user <username>",
	Short: "Update a user's info (superadmin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dto := api.UpdateUserProfileDTO{}
		dto.DisplayName, _ = cmd.Flags().GetString("display-name")
		dto.Email, _ = cmd.Flags().GetString("email")
		if err := client.SuperAdminUpdateUser(args[0], dto); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("User updated!"))
		return nil
	},
}

var superadminUpdateRoleCmd = &cobra.Command{
	Use:   "update-role <username> <role>",
	Short: "Update a user's role (superadmin) [role: 1=user, 2=admin, 3=superadmin]",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		role, err := parseRole(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		if err := client.SuperAdminUpdateUserRole(args[0], role); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Role updated!"))
		return nil
	},
}

var superadminDeleteUserCmd = &cobra.Command{
	Use:   "delete-user <username>",
	Short: "Delete a user (superadmin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		confirmed, err := ui.Confirm("Are you sure you want to delete user " + args[0] + "?")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Println(ui.Info("Cancelled."))
			return nil
		}
		if err := client.SuperAdminDeleteUser(args[0]); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("User deleted!"))
		return nil
	},
}

var superadminCountCACmd = &cobra.Command{
	Use:   "count-ca",
	Short: "Count CAs (superadmin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		condition, _ := cmd.Flags().GetString("condition")
		count, err := client.SuperAdminCountCAs(condition)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Label("CA Count", strconv.FormatInt(count, 10)))
		return nil
	},
}

var superadminCountCertCmd = &cobra.Command{
	Use:   "count-cert",
	Short: "Count SSL certificates (superadmin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		count, err := client.SuperAdminCountSSLCerts()
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Label("SSL Certificate Count", strconv.FormatInt(count, 10)))
		return nil
	},
}

func printSessionTable(sessions []api.LoginRecordDTO, total int64) {
	t := ui.NewTable([]ui.TableColumn{
		{Title: "UUID", Width: 36},
		{Title: "Username", Width: 16},
		{Title: "IP Address", Width: 15},
		{Title: "Browser", Width: 18},
		{Title: "Login Time", Width: 22},
		{Title: "Online", Width: 6},
	})
	for _, s := range sessions {
		online := "No"
		if s.IsOnline {
			online = "Yes"
		}
		t.AddRow([]string{s.UUID, s.Username, s.IPAddress, s.Browser, s.LoginTime, online})
	}
	fmt.Printf("Total: %d sessions\n", total)
	fmt.Println(t.Render())
}

func parseRole(roleStr string) (int32, error) {
	switch roleStr {
	case "user", "1":
		return 1, nil
	case "admin", "2":
		return 2, nil
	case "superadmin", "3":
		return 3, nil
	default:
		n, err := strconv.ParseInt(roleStr, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid role %q: use 1 (user), 2 (admin), or 3 (superadmin)", roleStr)
		}
		return int32(n), nil
	}
}

func init() {
	superadminSessionsCmd.Flags().String("status", "", "Filter by status")
	superadminSessionsCmd.Flags().Int("page", 1, "Page number")
	superadminSessionsCmd.Flags().Int("limit", 10, "Page size")

	superadminUserSessionsCmd.Flags().String("status", "", "Filter by status")
	superadminUserSessionsCmd.Flags().Int("page", 1, "Page number")
	superadminUserSessionsCmd.Flags().Int("limit", 10, "Page size")

	superadminCreateUserCmd.Flags().String("username", "", "Username")
	superadminCreateUserCmd.Flags().String("display-name", "", "Display name")
	superadminCreateUserCmd.Flags().String("email", "", "Email address")
	superadminCreateUserCmd.Flags().String("password", "", "Password (use interactive prompt if omitted)")
	superadminCreateUserCmd.Flags().String("role", "user", "Role (user/admin/superadmin or 1/2/3)")

	superadminUpdateUserCmd.Flags().String("display-name", "", "New display name")
	superadminUpdateUserCmd.Flags().String("email", "", "New email")

	superadminCountCACmd.Flags().String("condition", "", "Filter condition (none/available/unavailable)")

	superadminCmd.AddCommand(
		superadminSessionsCmd,
		superadminUserSessionsCmd,
		superadminForceLogoutCmd,
		superadminCreateUserCmd,
		superadminUpdateUserCmd,
		superadminUpdateRoleCmd,
		superadminDeleteUserCmd,
		superadminCountCACmd,
		superadminCountCertCmd,
	)
	rootCmd.AddCommand(superadminCmd)
}
