package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/gregPerlinLi/CertVaultCLI/internal/api"
	"github.com/spf13/cobra"
)

const version = "2.0.0"

var client *api.Client

var rootCmd = &cobra.Command{
	Use:   "cv",
	Short: "CertVault CLI — manage certificates with style",
	Long: lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true).Render(`
   ____          _  __     __          _ _    ____ _     ___ 
  / ___|___ _ __| |_\ \   / /_ _ _   _| | |_ / ___| |   |_ _|
 | |   / _ \ '__| __\ \ / / _' | | | | | __| |   | |    | | 
 | |__| __/ |  | |_ \ V / (_| | |_| | | |_| |___| |___ | | 
  \____\___|_|   \__| \_/ \__,_|\__,_|_|\__|\____|_____|___|
`) + "\n  CertVault CLI v" + version + " — Certificate Management Tool",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	var err error
	client, err = api.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize client: %v\n", err)
		os.Exit(1)
	}
}
