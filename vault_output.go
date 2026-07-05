package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func printVaultReport(report vaultReport, format outputFormat) {
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
		printVaultProm(report)
	default:
		printVaultRaw(report)
	}
}

func printVaultRaw(report vaultReport) {
	fmt.Printf("ca  %s %s\n", report.Provider, report.Action)
	fmt.Printf("url: %s\n", report.BaseURL)
	fmt.Printf("mount: %s\n", report.Mount)
	fmt.Printf("status: %s\n", statusColor(report.Status))
	if report.Health.Endpoint != "" {
		fmt.Printf("health: %s (%d, %s)\n", statusColor(yesNo(report.Health.Healthy)), report.Health.HTTPStatus, report.Health.Message)
	}
	if report.CA.Endpoint != "" {
		fmt.Printf("ca: %d certs", report.CA.Count)
		if report.CA.OutputPath != "" {
			fmt.Printf(" -> %s", report.CA.OutputPath)
		}
		fmt.Println()
	}
	fmt.Println()

	if len(report.CA.Certs) > 0 {
		rows := make([][]string, 0, len(report.CA.Certs))
		for _, cert := range report.CA.Certs {
			rows = append(rows, []string{
				shortIssuer(cert.Subject),
				shortIssuer(cert.Issuer),
				prettyTimestamp(cert.NotAfter),
				expiryVaultCell(cert),
				statusColor(yesNo(cert.IsCA)),
				cert.SHA256,
			})
		}
		renderTable([]string{"subject", "issuer", "expires_at", "expires_in", "ca", "sha256"}, rows)
		fmt.Println()
	}
	printVaultFindings(report.Findings)
}

func expiryVaultCell(cert vaultCert) string {
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

func printVaultFindings(findings []vaultFinding) {
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

func printVaultProm(report vaultReport) {
	fmt.Println("# HELP certops_ca_vault_status Vault CA aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE certops_ca_vault_status gauge")
	fmt.Println("# HELP certops_ca_vault_health_ok Vault health status.")
	fmt.Println("# TYPE certops_ca_vault_health_ok gauge")
	fmt.Println("# HELP certops_ca_vault_ca_total Vault CA certificate count.")
	fmt.Println("# TYPE certops_ca_vault_ca_total gauge")
	fmt.Println("# HELP certops_ca_vault_ca_days_left Days until Vault CA certificate expiration.")
	fmt.Println("# TYPE certops_ca_vault_ca_days_left gauge")
	for _, status := range []string{"ok", "warn", "critical"} {
		fmt.Printf("certops_ca_vault_status{%s} %d\n", promLabels(map[string]string{
			"action": report.Action,
			"mount":  report.Mount,
			"status": status,
			"url":    report.BaseURL,
		}), boolInt(report.Status == status))
	}
	if report.Health.Endpoint != "" {
		fmt.Printf("certops_ca_vault_health_ok{%s} %d\n", promLabels(map[string]string{"url": report.BaseURL}), boolInt(report.Health.Healthy))
	}
	if report.CA.Endpoint != "" {
		fmt.Printf("certops_ca_vault_ca_total{%s} %d\n", promLabels(map[string]string{"mount": report.Mount, "url": report.BaseURL}), report.CA.Count)
	}
	for _, cert := range report.CA.Certs {
		fmt.Printf("certops_ca_vault_ca_days_left{%s} %d\n", promLabels(map[string]string{
			"mount":   report.Mount,
			"sha256":  cert.SHA256,
			"subject": cert.Subject,
			"url":     report.BaseURL,
		}), cert.DaysLeft)
	}
}
