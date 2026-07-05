package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func printGenericCAReport(report genericCAReport, format outputFormat) {
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
		printGenericCAProm(report)
	default:
		printGenericCARaw(report)
	}
}

func printGenericCARaw(report genericCAReport) {
	fmt.Printf("ca  %s %s\n", report.Provider, report.Action)
	fmt.Printf("source: %s\n", report.Source)
	fmt.Printf("status: %s\n", statusColor(report.Status))
	fmt.Printf("ca: %d certs", report.CA.Count)
	if report.CA.OutputPath != "" {
		fmt.Printf(" -> %s", report.CA.OutputPath)
	}
	fmt.Println()
	fmt.Println()

	rows := make([][]string, 0, len(report.CA.Certs))
	for _, cert := range report.CA.Certs {
		rows = append(rows, []string{
			shortIssuer(cert.Subject),
			shortIssuer(cert.Issuer),
			prettyTimestamp(cert.NotAfter),
			expiryGenericCACell(cert),
			statusColor(yesNo(cert.IsCA)),
			cert.SHA256,
		})
	}
	renderTable([]string{"subject", "issuer", "expires_at", "expires_in", "ca", "sha256"}, rows)
	fmt.Println()
	printGenericCAFindings(report.Findings)
}

func expiryGenericCACell(cert genericCACert) string {
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

func printGenericCAFindings(findings []genericCAFinding) {
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

func printGenericCAProm(report genericCAReport) {
	fmt.Println("# HELP certops_ca_generic_status Generic CA aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE certops_ca_generic_status gauge")
	fmt.Println("# HELP certops_ca_generic_ca_total Generic CA certificate count.")
	fmt.Println("# TYPE certops_ca_generic_ca_total gauge")
	fmt.Println("# HELP certops_ca_generic_ca_days_left Days until generic CA certificate expiration.")
	fmt.Println("# TYPE certops_ca_generic_ca_days_left gauge")
	for _, status := range []string{"ok", "warn", "critical"} {
		fmt.Printf("certops_ca_generic_status{%s} %d\n", promLabels(map[string]string{
			"source": report.Source,
			"status": status,
		}), boolInt(report.Status == status))
	}
	fmt.Printf("certops_ca_generic_ca_total{%s} %d\n", promLabels(map[string]string{"source": report.Source}), report.CA.Count)
	for _, cert := range report.CA.Certs {
		fmt.Printf("certops_ca_generic_ca_days_left{%s} %d\n", promLabels(map[string]string{
			"sha256":  cert.SHA256,
			"source":  report.Source,
			"subject": cert.Subject,
		}), cert.DaysLeft)
	}
}
