package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/gregPerlinLi/CertVaultCLI/internal/api"
	"github.com/gregPerlinLi/CertVaultCLI/internal/ui"
	"github.com/spf13/cobra"
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage SSL certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var certListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your SSL certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyword, _ := cmd.Flags().GetString("keyword")
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		data, err := client.ListUserSSLCerts(keyword, page, limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to fetch certificates: "+err.Error()))
			os.Exit(1)
		}
		t := ui.NewTable([]ui.TableColumn{
			{Title: "UUID", Width: 36},
			{Title: "Comment", Width: 30},
			{Title: "Owner", Width: 14},
			{Title: "Expires", Width: 25},
		})
		for _, cert := range data.List {
			t.AddRow([]string{cert.UUID, cert.Comment, cert.Owner, cert.NotAfter})
		}
		fmt.Printf("Total: %d certificates\n", data.Total)
		fmt.Println(t.Render())
		return nil
	},
}

var certGetCertCmd = &cobra.Command{
	Use:   "get-cert <uuid>",
	Short: "Get SSL certificate content",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		isChain, _ := cmd.Flags().GetBool("chain")
		noRootCA, _ := cmd.Flags().GetBool("no-root-ca")
		outputPath, _ := cmd.Flags().GetString("output")
		analyze, _ := cmd.Flags().GetBool("analyze")

		certBase64, err := client.GetUserSSLCert(uuid, isChain, !noRootCA)
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

var certGetPrivKeyCmd = &cobra.Command{
	Use:   "get-privkey <uuid>",
	Short: "Get SSL certificate private key",
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

		privKeyBase64, err := client.GetUserSSLPrivKey(uuid, password)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to fetch private key: "+err.Error()))
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

var certUpdateCommentCmd = &cobra.Command{
	Use:   "update-comment <uuid> <comment>",
	Short: "Update SSL certificate comment",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		comment := args[1]
		err := client.UpdateSSLCertComment(uuid, comment)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Error("Failed to update comment: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println(ui.Success("Comment updated successfully!"))
		return nil
	},
}

// analyzeCert fetches and displays certificate analysis
func analyzeCert(certBase64 string) error {
	var analysis *api.CertAnalysisDTO
	err := ui.WithSpinner("Analyzing certificate...", func() error {
		var e error
		analysis, e = client.AnalyzeCertificate(certBase64)
		return e
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Error("Analysis failed: "+err.Error()))
		os.Exit(1)
	}
	fmt.Println(ui.TitleStyle.Render("Certificate Analysis"))
	fmt.Println(ui.Label("Subject", analysis.Subject))
	fmt.Println(ui.Label("Issuer", analysis.Issuer))
	fmt.Println(ui.Label("Not Before", analysis.NotBefore))
	fmt.Println(ui.Label("Not After", ui.FormatDate(analysis.NotAfter)))
	fmt.Println(ui.Label("Serial Number", analysis.SerialNumber))
	fmt.Println(ui.TitleStyle.Render("Public Key"))
	fmt.Println(ui.Label("Algorithm", analysis.PublicKey.Algorithm))
	fmt.Println(ui.Label("Format", analysis.PublicKey.Format))
	// RSA-specific fields
	if analysis.PublicKey.Modulus != "" {
		fmt.Println(ui.Label("Modulus", analysis.PublicKey.Modulus))
		fmt.Println(ui.Label("Public Exponent", analysis.PublicKey.Exponent))
	}
	// ECC-specific: JCE W point
	if analysis.PublicKey.W != nil {
		fmt.Println(ui.Label("EC Point W (Affine X)", analysis.PublicKey.W.AffineX))
		fmt.Println(ui.Label("EC Point W (Affine Y)", analysis.PublicKey.W.AffineY))
	}
	// ECC-specific: BouncyCastle Q point
	if analysis.PublicKey.Q != nil {
		fmt.Println(ui.Label("EC Point Q (X)", analysis.PublicKey.Q.X))
		fmt.Println(ui.Label("EC Point Q (Y)", analysis.PublicKey.Q.Y))
		fmt.Println(ui.Label("EC Coordinate System", analysis.PublicKey.Q.CoordinateSystem))
	}
	// Ed25519-specific point
	if analysis.PublicKey.Point != nil {
		fmt.Println(ui.Label("Ed25519 Point (Y)", analysis.PublicKey.Point.Y))
		fmt.Printf("%s  %v\n", ui.LabelStyle.Render("Ed25519 X Odd:"), analysis.PublicKey.Point.XOdd)
	}
	// Params: render raw JSON (null / string / object)
	if len(analysis.PublicKey.Params) > 0 && string(analysis.PublicKey.Params) != "null" {
		fmt.Println(ui.Label("Params", string(analysis.PublicKey.Params)))
	}
	if len(analysis.Extensions) > 0 {
		fmt.Println(ui.TitleStyle.Render("Extensions"))
		for k, v := range analysis.Extensions {
			fmt.Println(ui.Label(k, v))
		}
	}
	return nil
}

// outputData writes data to file or stdout
func outputData(data []byte, outputPath, successMsg string) error {
	if outputPath == "" {
		fmt.Print(string(data))
		return nil
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		fmt.Fprintln(os.Stderr, ui.Error("Failed to write file: "+err.Error()))
		os.Exit(1)
	}
	fmt.Println(ui.Success(successMsg + outputPath))
	return nil
}

func init() {
	certListCmd.Flags().StringP("keyword", "k", "", "Search keyword")
	certListCmd.Flags().Int("page", 1, "Page number")
	certListCmd.Flags().Int("limit", 10, "Page size")

	certGetCertCmd.Flags().Bool("chain", false, "Get certificate chain")
	certGetCertCmd.Flags().Bool("no-root-ca", false, "Exclude root CA from chain")
	certGetCertCmd.Flags().StringP("output", "o", "", "Output file path")
	certGetCertCmd.Flags().BoolP("analyze", "a", false, "Analyze certificate details")

	certGetPrivKeyCmd.Flags().StringP("password", "p", "", "Password for private key decryption")
	certGetPrivKeyCmd.Flags().StringP("output", "o", "", "Output file path")

	certCmd.AddCommand(certListCmd, certGetCertCmd, certGetPrivKeyCmd, certUpdateCommentCmd)
	rootCmd.AddCommand(certCmd)
}
