package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func ttyStdout() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func colorEnabled() bool {
	return ttyStdout() && strings.TrimSpace(os.Getenv("NO_COLOR")) == ""
}

func colorize(s, code string) string {
	if !colorEnabled() {
		return s
	}
	return code + s + "\x1b[0m"
}

func statusColor(status string) string {
	switch strings.ToLower(status) {
	case "ok", "trusted", "matches", "yes", "present":
		return colorize(status, "\x1b[32m")
	case "warn", "warning", "missing", "not confirmed":
		return colorize(status, "\x1b[33m")
	case "critical", "error", "fail", "failed", "untrusted", "mismatch", "no":
		return colorize(status, "\x1b[31m")
	default:
		return status
	}
}

func padRule(width int) string {
	if width <= 0 {
		return ""
	}
	return strings.Repeat("─", width)
}

func renderTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && visibleLen(cell) > widths[i] {
				widths[i] = visibleLen(cell)
			}
		}
	}
	for i, h := range headers {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Printf("%-*s", widths[i], h)
	}
	fmt.Println()
	for i, w := range widths {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Print(padRule(w))
	}
	fmt.Println()
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Print("  ")
			}
			fmt.Printf("%-*s", widths[i]+len(cell)-visibleLen(cell), cell)
		}
		fmt.Println()
	}
}

func visibleLen(s string) int {
	return len(ansiPattern.ReplaceAllString(s, ""))
}
