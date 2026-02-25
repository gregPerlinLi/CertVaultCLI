package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// TableColumn defines a table column
type TableColumn struct {
	Title string
	Width int
}

// Table renders a simple ASCII table with lipgloss styling
type Table struct {
	Columns []TableColumn
	Rows    [][]string
}

// NewTable creates a new table
func NewTable(columns []TableColumn) *Table {
	return &Table{Columns: columns}
}

// AddRow adds a row to the table
func (t *Table) AddRow(row []string) {
	t.Rows = append(t.Rows, row)
}

// Render renders the table as a string
func (t *Table) Render() string {
	var sb strings.Builder

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)
	borderStyle := lipgloss.NewStyle().Foreground(ColorMuted)
	cellStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F3F4F6"))

	// Build separator
	sep := borderStyle.Render("+")
	for _, col := range t.Columns {
		sep += borderStyle.Render(strings.Repeat("-", col.Width+2) + "+")
	}

	sb.WriteString(sep + "\n")

	// Header
	header := borderStyle.Render("|")
	for _, col := range t.Columns {
		title := col.Title
		if len(title) > col.Width {
			title = title[:col.Width]
		}
		header += " " + headerStyle.Render(fmt.Sprintf("%-*s", col.Width, title)) + " " + borderStyle.Render("|")
	}
	sb.WriteString(header + "\n")
	sb.WriteString(sep + "\n")

	// Rows
	for _, row := range t.Rows {
		line := borderStyle.Render("|")
		for i, col := range t.Columns {
			var cell string
			if i < len(row) {
				cell = row[i]
			}
			if len(cell) > col.Width {
				cell = cell[:col.Width-3] + "..."
			}
			line += " " + cellStyle.Render(fmt.Sprintf("%-*s", col.Width, cell)) + " " + borderStyle.Render("|")
		}
		sb.WriteString(line + "\n")
	}

	sb.WriteString(sep)
	return sb.String()
}

// DateColor returns the color for a certificate expiry date
func DateColor(notAfter string) lipgloss.Style {
	t, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		// Try other common formats
		for _, layout := range []string{"2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "2006-01-02"} {
			t, err = time.Parse(layout, notAfter)
			if err == nil {
				break
			}
		}
		if err != nil {
			return lipgloss.NewStyle()
		}
	}
	now := time.Now()
	if t.Before(now) {
		return lipgloss.NewStyle().Foreground(ColorError)
	}
	if t.Before(now.Add(30 * 24 * time.Hour)) {
		return lipgloss.NewStyle().Foreground(ColorWarning)
	}
	return lipgloss.NewStyle().Foreground(ColorSuccess)
}

// FormatDate formats a date string for display with color coding
func FormatDate(notAfter string) string {
	return DateColor(notAfter).Render(notAfter)
}
