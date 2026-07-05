package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func printTrustReport(report trustReport, format outputFormat) {
	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		enc := yaml.NewEncoder(os.Stdout)
		defer enc.Close()
		if err := enc.Encode(report); err != nil {
			fatal(err.Error())
		}
	case outputProm:
		printTrustProm(report)
	default:
		printTrustRaw(report)
	}
}

func printTrustRaw(report trustReport) {
	fmt.Printf("trust  %s\n", report.Action)
	fmt.Printf("source: %s\n", report.Source)
	fmt.Printf("store: %s\n", report.Store)
	fmt.Printf("status: %s\n", statusColor(report.Status))
	if report.InstallPath != "" {
		fmt.Printf("install_path: %s\n", report.InstallPath)
	}
	fmt.Println()

	rows := make([][]string, 0, len(report.Certs))
	for _, cert := range report.Certs {
		rows = append(rows, []string{
			shortIssuer(cert.Subject),
			shortIssuer(cert.Issuer),
			prettyTimestamp(cert.NotAfter),
			expiryTrustCell(cert),
			statusColor(yesNo(cert.IsCA)),
			statusColor(yesNo(cert.Installed)),
			cert.SHA256,
		})
	}
	renderTable([]string{"subject", "issuer", "expires_at", "expires_in", "ca", "installed", "sha256"}, rows)

	if len(report.Commands) > 0 {
		fmt.Println("\ncommands:")
		for _, cmd := range report.Commands {
			fmt.Printf("  %s\n", cmd)
		}
	}
	fmt.Println()
	printTrustFindings(report.Findings)
}

func expiryTrustCell(cert trustCert) string {
	value := fmt.Sprintf("%d days", cert.DaysLeft)
	switch {
	case cert.DaysLeft < 0:
		return colorize(value, "\x1b[31m")
	case cert.DaysLeft < 30:
		return colorize(value, "\x1b[33m")
	default:
		return colorize(value, "\x1b[32m")
	}
}

func printTrustFindings(findings []trustFinding) {
	fmt.Println("findings:")
	if len(findings) == 0 {
		fmt.Println("  none")
		return
	}
	rows := make([][]string, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, []string{statusColor(finding.Severity), finding.Message})
	}
	renderTable([]string{"severity", "message"}, rows)
}

func printTrustProm(report trustReport) {
	fmt.Println("# HELP certops_trust_status Trust-store operation status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE certops_trust_status gauge")
	fmt.Println("# HELP certops_trust_certificate_days_left Days until CA certificate expiration.")
	fmt.Println("# TYPE certops_trust_certificate_days_left gauge")
	fmt.Println("# HELP certops_trust_certificate_installed CA certificate install status.")
	fmt.Println("# TYPE certops_trust_certificate_installed gauge")
	for _, status := range []string{"ok", "warn", "critical"} {
		fmt.Printf("certops_trust_status{%s} %d\n", promLabels(map[string]string{
			"action": report.Action,
			"source": report.Source,
			"status": status,
		}), boolInt(report.Status == status))
	}
	for _, cert := range report.Certs {
		labels := map[string]string{"source": report.Source, "subject": cert.Subject, "sha256": cert.SHA256}
		fmt.Printf("certops_trust_certificate_days_left{%s} %d\n", promLabels(labels), cert.DaysLeft)
		fmt.Printf("certops_trust_certificate_installed{%s} %d\n", promLabels(labels), boolInt(cert.Installed))
	}
}
