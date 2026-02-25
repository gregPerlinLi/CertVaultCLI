package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/gregPerlinLi/CertVaultCLI/internal/api"
	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Admin-only commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var adminUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List all users (admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyword, _ := cmd.Flags().GetString("keyword")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		data, err := client.AdminListUsers(keyword, page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		t := ui.NewTable([]ui.TableColumn{
			{Title: "Username", Width: 20},
			{Title: "Display Name", Width: 25},
			{Title: "Email", Width: 30},
			{Title: "Role", Width: 12},
		})
		for _, u := range data.List {
			t.AddRow([]string{u.Username, u.DisplayName, u.Email, u.RoleName()})
		}
		fmt.Printf("Total: %d users\n", data.Total)
		fmt.Println(t.Render())
		return nil
	},
}

var adminCACmd = &cobra.Command{
	Use:   "ca",
	Short: "CA management commands (admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var adminCAListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all CAs (admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyword, _ := cmd.Flags().GetString("keyword")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		data, err := client.AdminListCAs(keyword, page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		t := ui.NewTable([]ui.TableColumn{
			{Title: "UUID", Width: 36},
			{Title: "Owner", Width: 14},
			{Title: "Type", Width: 8},
			{Title: "Comment", Width: 30},
			{Title: "Expires", Width: 25},
			{Title: "Avail", Width: 5},
		})
		for _, ca := range data.List {
			avail := "Yes"
			if !ca.Available {
				avail = "No"
			}
			t.AddRow([]string{ca.UUID, ca.Owner, ui.FormatCAType(ca.CAType()), ca.Comment, ui.FormatDate(ca.NotAfter), avail})
		}
		fmt.Printf("Total: %d CAs\n", data.Total)
		fmt.Println(t.Render())
		return nil
	},
}

var adminCAGetCertCmd = &cobra.Command{
	Use:   "get-cert <uuid>",
	Short: "Get CA certificate (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		isChain, _ := cmd.Flags().GetBool("chain")
		noRootCA, _ := cmd.Flags().GetBool("no-root-ca")
		outputPath, _ := cmd.Flags().GetString("output")
		analyze, _ := cmd.Flags().GetBool("analyze")

		certBase64, err := client.AdminGetCACert(uuid, isChain, !noRootCA)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		if analyze {
			return analyzeCert(certBase64)
		}
		certPEM, err := base64.StdEncoding.DecodeString(certBase64)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to decode certificate: "+err.Error()))
			os.Exit(1)
		}
		return outputData(certPEM, outputPath, "Certificate saved to ")
	},
}

var adminCAGetPrivKeyCmd = &cobra.Command{
	Use:   "get-privkey <uuid>",
	Short: "Get CA private key (admin, requires password)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		password, _ := cmd.Flags().GetString("password")
		outputPath, _ := cmd.Flags().GetString("output")

		if password == "" {
			var err error
			password, err = ui.ReadPassword("Password: ")
			if err != nil {
				return err
			}
		}
		privKeyBase64, err := client.AdminGetCAPrivKey(uuid, password)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		privKeyPEM, err := base64.StdEncoding.DecodeString(privKeyBase64)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to decode private key: "+err.Error()))
			os.Exit(1)
		}
		return outputData(privKeyPEM, outputPath, "Private key saved to ")
	},
}

var adminCAUpdateCommentCmd = &cobra.Command{
	Use:   "update-comment <uuid> <comment>",
	Short: "Update CA comment (admin)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := client.AdminUpdateCAComment(args[0], args[1]); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Comment updated!"))
		return nil
	},
}

var adminCAToggleAvailCmd = &cobra.Command{
	Use:   "toggle-available <uuid>",
	Short: "Toggle CA availability (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := client.AdminToggleCAAvailable(args[0]); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("CA availability toggled!"))
		return nil
	},
}

var adminCAImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import CA certificate (admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		certFile, _ := cmd.Flags().GetString("cert-file")
		keyFile, _ := cmd.Flags().GetString("key-file")
		comment, _ := cmd.Flags().GetString("comment")

		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to read cert file: "+err.Error()))
			os.Exit(1)
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to read key file: "+err.Error()))
			os.Exit(1)
		}

		dto := api.ImportCADTO{
			Certificate: base64.StdEncoding.EncodeToString(certPEM),
			PrivKey:     base64.StdEncoding.EncodeToString(keyPEM),
			Comment:     comment,
		}
		if err := client.AdminImportCA(dto); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("CA imported successfully!"))
		return nil
	},
}

var adminCABindCmd = &cobra.Command{
	Use:   "bind <ca-uuid> <username...>",
	Short: "Bind users to CA (admin)",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		caUUID := args[0]
		usernames := args[1:]
		if err := client.AdminBindUsersToCA(caUUID, usernames); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Users bound to CA: " + strings.Join(usernames, ", ")))
		return nil
	},
}

var adminCAUnbindCmd = &cobra.Command{
	Use:   "unbind <ca-uuid> <username...>",
	Short: "Unbind users from CA (admin)",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		caUUID := args[0]
		usernames := args[1:]
		if err := client.AdminUnbindUsersFromCA(caUUID, usernames); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Users unbound from CA: " + strings.Join(usernames, ", ")))
		return nil
	},
}

var adminCABoundUsersCmd = &cobra.Command{
	Use:   "bound-users <ca-uuid>",
	Short: "List users bound to CA (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")
		data, err := client.AdminGetCABoundUsers(args[0], page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		t := ui.NewTable([]ui.TableColumn{
			{Title: "Username", Width: 20},
			{Title: "Display Name", Width: 25},
			{Title: "Email", Width: 30},
			{Title: "Role", Width: 12},
		})
		for _, u := range data.List {
			t.AddRow([]string{u.Username, u.DisplayName, u.Email, u.RoleName()})
		}
		fmt.Printf("Total: %d users\n", data.Total)
		fmt.Println(t.Render())
		return nil
	},
}

var adminCAUnboundUsersCmd = &cobra.Command{
	Use:   "unbound-users <ca-uuid>",
	Short: "List users not bound to CA (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")
		data, err := client.AdminGetCAUnboundUsers(args[0], page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		t := ui.NewTable([]ui.TableColumn{
			{Title: "Username", Width: 20},
			{Title: "Display Name", Width: 25},
			{Title: "Email", Width: 30},
			{Title: "Role", Width: 12},
		})
		for _, u := range data.List {
			t.AddRow([]string{u.Username, u.DisplayName, u.Email, u.RoleName()})
		}
		fmt.Printf("Total: %d users\n", data.Total)
		fmt.Println(t.Render())
		return nil
	},
}

var adminCACreateRootCmd = &cobra.Command{
	Use:   "create-root",
	Short: "Create a root CA (admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dto := api.RequestCertDTO{}
		dto.Comment, _ = cmd.Flags().GetString("comment")
		dto.AllowSubCa, _ = cmd.Flags().GetBool("allow-sub-ca")
		dto.Algorithm, _ = cmd.Flags().GetString("algorithm")
		dto.KeySize, _ = cmd.Flags().GetInt("key-size")
		dto.Country, _ = cmd.Flags().GetString("country")
		dto.Province, _ = cmd.Flags().GetString("province")
		dto.City, _ = cmd.Flags().GetString("city")
		dto.Organization, _ = cmd.Flags().GetString("organization")
		dto.OrganizationalUnit, _ = cmd.Flags().GetString("org-unit")
		dto.CommonName, _ = cmd.Flags().GetString("common-name")
		dto.Expiry, _ = cmd.Flags().GetInt("expiry")
		if err := client.AdminCreateRootCA(dto); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Root CA created successfully!"))
		return nil
	},
}

var adminCACreateIntCmd = &cobra.Command{
	Use:   "create-int",
	Short: "Create an intermediate CA (admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dto := api.RequestCertDTO{}
		dto.CaUUID, _ = cmd.Flags().GetString("parent-ca")
		dto.Comment, _ = cmd.Flags().GetString("comment")
		dto.AllowSubCa, _ = cmd.Flags().GetBool("allow-sub-ca")
		dto.Algorithm, _ = cmd.Flags().GetString("algorithm")
		dto.KeySize, _ = cmd.Flags().GetInt("key-size")
		dto.Country, _ = cmd.Flags().GetString("country")
		dto.Province, _ = cmd.Flags().GetString("province")
		dto.City, _ = cmd.Flags().GetString("city")
		dto.Organization, _ = cmd.Flags().GetString("organization")
		dto.OrganizationalUnit, _ = cmd.Flags().GetString("org-unit")
		dto.CommonName, _ = cmd.Flags().GetString("common-name")
		dto.Expiry, _ = cmd.Flags().GetInt("expiry")
		if err := client.AdminCreateIntCA(dto); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Intermediate CA created successfully!"))
		return nil
	},
}

var adminCARenewCmd = &cobra.Command{
	Use:   "renew <uuid>",
	Short: "Renew a CA certificate (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		expiry, _ := cmd.Flags().GetInt("expiry")
		if err := client.AdminRenewCA(args[0], expiry); err != nil {
			fmt.Fprintln(os.Stderr, ui.Error(err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("CA certificate renewed successfully!"))
		return nil
	},
}

func init() {
	adminUsersCmd.Flags().StringP("keyword", "k", "", "Search keyword")
	adminUsersCmd.Flags().Int("page", 1, "Page number")
	adminUsersCmd.Flags().Int("limit", 10, "Page size")

	adminCAListCmd.Flags().StringP("keyword", "k", "", "Search keyword")
	adminCAListCmd.Flags().Int("page", 1, "Page number")
	adminCAListCmd.Flags().Int("limit", 10, "Page size")

	adminCAGetCertCmd.Flags().Bool("chain", false, "Get certificate chain")
	adminCAGetCertCmd.Flags().Bool("no-root-ca", false, "Exclude root CA from chain")
	adminCAGetCertCmd.Flags().StringP("output", "o", "", "Output file path")
	adminCAGetCertCmd.Flags().BoolP("analyze", "a", false, "Analyze certificate details")

	adminCAGetPrivKeyCmd.Flags().StringP("password", "p", "", "Password")
	adminCAGetPrivKeyCmd.Flags().StringP("output", "o", "", "Output file path")

	adminCAImportCmd.Flags().String("cert-file", "", "Path to CA certificate PEM file")
	adminCAImportCmd.Flags().String("key-file", "", "Path to private key PEM file")
	adminCAImportCmd.Flags().String("comment", "", "CA comment")

	adminCABoundUsersCmd.Flags().Int("page", 1, "Page number")
	adminCABoundUsersCmd.Flags().Int("limit", 10, "Page size")
	adminCAUnboundUsersCmd.Flags().Int("page", 1, "Page number")
	adminCAUnboundUsersCmd.Flags().Int("limit", 10, "Page size")

	caCreateFlags := func(cmd *cobra.Command) {
		cmd.Flags().String("comment", "", "CA comment")
		cmd.Flags().Bool("allow-sub-ca", false, "Allow creating sub-CAs")
		cmd.Flags().String("algorithm", "RSA", "Key algorithm (RSA/EC/Ed25519)")
		cmd.Flags().Int("key-size", 2048, "Key size")
		cmd.Flags().String("country", "", "Country code (e.g. CN)")
		cmd.Flags().String("province", "", "Province/State")
		cmd.Flags().String("city", "", "City/Locality")
		cmd.Flags().String("organization", "", "Organization")
		cmd.Flags().String("org-unit", "", "Organizational unit")
		cmd.Flags().String("common-name", "", "Common name")
		cmd.Flags().Int("expiry", 365, "Validity period in days")
	}
	caCreateFlags(adminCACreateRootCmd)
	caCreateFlags(adminCACreateIntCmd)
	adminCACreateIntCmd.Flags().String("parent-ca", "", "Parent CA UUID")

	adminCARenewCmd.Flags().Int("expiry", 365, "New validity period in days")

	adminCACmd.AddCommand(
		adminCAListCmd,
		adminCAGetCertCmd,
		adminCAGetPrivKeyCmd,
		adminCAUpdateCommentCmd,
		adminCAToggleAvailCmd,
		adminCAImportCmd,
		adminCABindCmd,
		adminCAUnbindCmd,
		adminCABoundUsersCmd,
		adminCAUnboundUsersCmd,
		adminCACreateRootCmd,
		adminCACreateIntCmd,
		adminCARenewCmd,
	)
	adminCmd.AddCommand(adminUsersCmd, adminCACmd)
	rootCmd.AddCommand(adminCmd)
}
