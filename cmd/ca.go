package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage CA certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var caListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your allocated CA certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyword, _ := cmd.Flags().GetString("keyword")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		data, err := client.ListUserCAs(keyword, page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to fetch CAs: "+err.Error()))
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
			t.AddRow([]string{ca.UUID, ca.Owner, ca.CAType(), ca.Comment, ca.NotAfter, avail})
		}
		fmt.Printf("Total: %d CAs\n", data.Total)
		fmt.Println(t.Render())
		return nil
	},
}

var caGetInfoCmd = &cobra.Command{
	Use:   "get <uuid>",
	Short: "Show detailed info for a CA certificate",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		info, err := client.GetUserCACertInfo(uuid)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to fetch CA info: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.TitleStyle.Render("CA Certificate Info"))
		fmt.Println(ui.Label("UUID", info.UUID))
		fmt.Println(ui.Label("Owner", info.Owner))
		fmt.Println(ui.Label("Type", info.CAType()))
		fmt.Println(ui.Label("Comment", info.Comment))
		fmt.Println(ui.Label("Available", fmt.Sprintf("%v", info.Available)))
		fmt.Println(ui.Label("Not Before", info.NotBefore))
		fmt.Println(ui.Label("Not After", ui.FormatDate(info.NotAfter)))
		if info.ParentCa != "" {
			fmt.Println(ui.Label("Parent CA", info.ParentCa))
		}
		return nil
	},
}

var caGetCertCmd = &cobra.Command{
	Use:   "get-cert <uuid>",
	Short: "Get CA certificate content",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		isChain, _ := cmd.Flags().GetBool("chain")
		noRootCA, _ := cmd.Flags().GetBool("no-root-ca")
		outputPath, _ := cmd.Flags().GetString("output")
		analyze, _ := cmd.Flags().GetBool("analyze")

		var certBase64 string
		err := ui.WithSpinner("Fetching certificate...", func() error {
			var e error
			certBase64, e = client.GetUserCACert(uuid, isChain, !noRootCA)
			return e
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to fetch certificate: "+err.Error()))
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

func init() {
	caListCmd.Flags().StringP("keyword", "k", "", "Search keyword")
	caListCmd.Flags().Int("page", 1, "Page number")
	caListCmd.Flags().Int("limit", 10, "Page size")

	caGetCertCmd.Flags().Bool("chain", false, "Get certificate chain")
	caGetCertCmd.Flags().Bool("no-root-ca", false, "Exclude root CA from chain")
	caGetCertCmd.Flags().StringP("output", "o", "", "Output file path")
	caGetCertCmd.Flags().BoolP("analyze", "a", false, "Analyze certificate details")

	caCmd.AddCommand(caListCmd, caGetInfoCmd, caGetCertCmd)
	rootCmd.AddCommand(caCmd)
}
