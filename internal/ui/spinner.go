package ui

import (
	"fmt"
	"os"
	"time"
)

// WithSpinner runs a function with a spinner animation
func WithSpinner(label string, fn func() error) error {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan error, 1)

	go func() {
		done <- fn()
	}()

	i := 0
	for {
		select {
		case err := <-done:
			fmt.Fprintf(os.Stderr, "\r\033[K")
			return err
		case <-time.After(80 * time.Millisecond):
			fmt.Fprintf(os.Stderr, "\r%s %s", InfoStyle.Render(frames[i%len(frames)]), MutedStyle.Render(label))
			i++
		}
	}
}
