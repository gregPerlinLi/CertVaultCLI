package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ReadLine reads a line of input with a prompt
func ReadLine(prompt string) (string, error) {
	fmt.Print(InfoStyle.Render(prompt))
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ReadPassword reads a password with masking
func ReadPassword(prompt string) (string, error) {
	fmt.Print(InfoStyle.Render(prompt))
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}

// Confirm asks for a yes/no confirmation
func Confirm(prompt string) (bool, error) {
	answer, err := ReadLine(prompt + " [y/N]: ")
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
