// Package render contains small, dependency-free helpers for clean terminal
// output: ANSI colour (auto-disabled when not a TTY or NO_COLOR is set),
// section headers, key/value rows, simple tables, and human byte formatting.
package render

import (
	"fmt"
	"os"
	"strings"
)

var useColor = detectColor()

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	// Enable colour only when stdout is a character device (a terminal).
	return fi.Mode()&os.ModeCharDevice != 0
}

// SetColor lets callers force colour on/off (e.g. a --no-color flag).
func SetColor(on bool) { useColor = on }

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
)

func c(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + reset
}

func Bold(s string) string   { return c(bold, s) }
func Dim(s string) string    { return c(dim, s) }
func Red(s string) string    { return c(red, s) }
func Green(s string) string  { return c(green, s) }
func Yellow(s string) string { return c(yellow, s) }
func Blue(s string) string   { return c(blue, s) }
func Cyan(s string) string   { return c(cyan, s) }

// Section prints a titled header bar.
func Section(title string) {
	fmt.Println()
	fmt.Println(c(cyan, "┌─ "+c(bold, title)+" "+strings.Repeat("─", max(0, 52-len(title)))))
}

// KV prints an aligned key/value row beneath a section.
func KV(key, value string) {
	fmt.Printf("%s %-22s %s\n", c(cyan, "│"), c(dim, key), value)
}

// Line prints a free-form indented line within a section.
func Line(s string) {
	fmt.Printf("%s %s\n", c(cyan, "│"), s)
}

// EndSection closes the visual block.
func EndSection() {
	fmt.Println(c(cyan, "└"+strings.Repeat("─", 56)))
}

// Bytes renders a byte count in a human-friendly unit.
func Bytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Bar renders a proportional usage bar of the given width.
func Bar(fraction float64, width int) string {
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	filled := int(fraction * float64(width))
	color := green
	switch {
	case fraction >= 0.9:
		color = red
	case fraction >= 0.7:
		color = yellow
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return c(color, bar) + fmt.Sprintf(" %5.1f%%", fraction*100)
}

// Severity tags for scan findings.
func Severity(level string) string {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return c(red, c(bold, "DEVOURED"))
	case "HIGH":
		return c(red, "HIGH")
	case "MEDIUM":
		return c(yellow, "MEDIUM")
	case "LOW":
		return c(blue, "LOW")
	case "PASS", "OK":
		return c(green, "WORTHY")
	default:
		return level
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
