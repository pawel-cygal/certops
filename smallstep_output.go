package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func printSmallstepReport(report smallstepReport, format outputFormat) {
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
		printSmallstepProm(report)
	default:
		printSmallstepRaw(report)
	}
}

func printSmallstepRaw(report smallstepReport) {
	fmt.Printf("ca  %s %s\n", report.Provider, report.Action)
	fmt.Printf("url: %s\n", report.BaseURL)
	fmt.Printf("status: %s\n", statusColor(report.Status))
	if report.Health.Endpoint != "" {
		fmt.Printf("health: %s (%d)\n", statusColor(yesNo(report.Health.Healthy)), report.Health.HTTPStatus)
	}
	if report.Roots.Endpoint != "" {
		fmt.Printf("roots: %d certs", report.Roots.Count)
		if report.Roots.OutputPath != "" {
			fmt.Printf(" -> %s", report.Roots.OutputPath)
		}
		fmt.Println()
	}
	fmt.Println()

	if len(report.Roots.Certs) > 0 {
		rows := make([][]string, 0, len(report.Roots.Certs))
		for _, cert := range report.Roots.Certs {
			rows = append(rows, []string{
				shortIssuer(cert.Subject),
				shortIssuer(cert.Issuer),
				prettyTimestamp(cert.NotAfter),
				expirySmallstepCell(cert),
				statusColor(yesNo(cert.IsCA)),
				cert.SHA256,
			})
		}
		renderTable([]string{"subject", "issuer", "expires_at", "expires_in", "ca", "sha256"}, rows)
		fmt.Println()
	}
	printSmallstepFindings(report.Findings)
}

func expirySmallstepCell(cert smallstepCert) string {
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

func printSmallstepFindings(findings []smallstepFinding) {
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

func printSmallstepProm(report smallstepReport) {
	fmt.Println("# HELP certops_ca_smallstep_status Smallstep CA aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE certops_ca_smallstep_status gauge")
	fmt.Println("# HELP certops_ca_smallstep_health_ok Smallstep health status.")
	fmt.Println("# TYPE certops_ca_smallstep_health_ok gauge")
	fmt.Println("# HELP certops_ca_smallstep_roots_total Smallstep roots count.")
	fmt.Println("# TYPE certops_ca_smallstep_roots_total gauge")
	fmt.Println("# HELP certops_ca_smallstep_root_days_left Days until Smallstep root certificate expiration.")
	fmt.Println("# TYPE certops_ca_smallstep_root_days_left gauge")
	for _, status := range []string{"ok", "warn", "critical"} {
		fmt.Printf("certops_ca_smallstep_status{%s} %d\n", promLabels(map[string]string{
			"action": report.Action,
			"url":    report.BaseURL,
			"status": status,
		}), boolInt(report.Status == status))
	}
	if report.Health.Endpoint != "" {
		fmt.Printf("certops_ca_smallstep_health_ok{%s} %d\n", promLabels(map[string]string{"url": report.BaseURL}), boolInt(report.Health.Healthy))
	}
	if report.Roots.Endpoint != "" {
		fmt.Printf("certops_ca_smallstep_roots_total{%s} %d\n", promLabels(map[string]string{"url": report.BaseURL}), report.Roots.Count)
	}
	for _, cert := range report.Roots.Certs {
		fmt.Printf("certops_ca_smallstep_root_days_left{%s} %d\n", promLabels(map[string]string{
			"sha256":  cert.SHA256,
			"subject": cert.Subject,
			"url":     report.BaseURL,
		}), cert.DaysLeft)
	}
}
