package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	ColorPrimary = lipgloss.Color("#7C3AED") // Purple
	ColorSuccess = lipgloss.Color("#22C55E") // Green
	ColorWarning = lipgloss.Color("#F59E0B") // Yellow/Amber
	ColorError   = lipgloss.Color("#EF4444") // Red
	ColorMuted   = lipgloss.Color("#6B7280") // Gray
	ColorInfo    = lipgloss.Color("#3B82F6") // Blue

	// Styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1)

	BannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 2)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)

	InfoStyle = lipgloss.NewStyle().
			Foreground(ColorInfo)

	MutedStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	LabelStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Width(20)

	ValueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F3F4F6"))

	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(ColorMuted)
)

// Success formats a success message
func Success(msg string) string {
	return SuccessStyle.Render("✅ " + msg)
}

// Error formats an error message
func Error(msg string) string {
	return ErrorStyle.Render("❌ " + msg)
}

// Warning formats a warning message
func Warning(msg string) string {
	return WarningStyle.Render("⚠️  " + msg)
}

// Info formats an info message
func Info(msg string) string {
	return InfoStyle.Render("ℹ️  " + msg)
}

// Label formats a label-value pair
func Label(label, value string) string {
	return LabelStyle.Render(label+":") + "  " + ValueStyle.Render(value)
}
