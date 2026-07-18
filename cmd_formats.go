package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	checker "certops/internal/check"
)

func printYAMLReports(reports []checker.Report) {
	fmt.Println("reports:")
	for _, report := range reports {
		fmt.Printf("  - target: %q\n", report.Target)
		fmt.Printf("    host: %q\n", report.Host)
		fmt.Printf("    status: %q\n", report.Status)
		if report.Error != "" {
			fmt.Printf("    error: %q\n", report.Error)
		}
		fmt.Println("    certificate:")
		fmt.Printf("      subject: %q\n", report.Certificate.Subject)
		fmt.Printf("      issuer: %q\n", report.Certificate.Issuer)
		fmt.Printf("      not_after: %q\n", report.Certificate.NotAfter)
		fmt.Printf("      days_remaining: %d\n", report.Certificate.DaysRemaining)
		fmt.Printf("      trusted: %t\n", report.Certificate.Trusted)
		fmt.Printf("      matches_host: %t\n", report.Certificate.MatchesHost)
		fmt.Println("      dns_names:")
		for _, name := range report.Certificate.DNSNames {
			fmt.Printf("        - %q\n", name)
		}
		fmt.Println("    tls:")
		fmt.Printf("      negotiated_version: %q\n", report.TLS.NegotiatedVersion)
		fmt.Printf("      cipher_suite: %q\n", report.TLS.CipherSuite)
		fmt.Printf("      alpn: %q\n", report.TLS.ALPN)
		fmt.Printf("      ocsp_stapling: %t\n", report.TLS.OCSPStapling)
		fmt.Printf("      handshake_ms: %d\n", report.TLS.HandshakeMS)
		fmt.Println("      supported_versions:")
		for _, version := range report.TLS.SupportedVersions {
			fmt.Printf("        - %q\n", version)
		}
		fmt.Println("    https:")
		fmt.Printf("      http_redirect_ok: %t\n", report.HTTPS.HTTPRedirectOK)
		fmt.Printf("      hsts: %q\n", report.HTTPS.HSTS)
		fmt.Println("    revocation:")
		fmt.Printf("      checked: %t\n", report.Revocation.Checked)
		fmt.Printf("      revoked: %t\n", report.Revocation.Revoked)
		fmt.Println("      sources:")
		for _, source := range report.Revocation.Sources {
			fmt.Printf("        - %q\n", source)
		}
		fmt.Println("      errors:")
		for _, err := range report.Revocation.Errors {
			fmt.Printf("        - %q\n", err)
		}
		fmt.Println("    findings:")
		for _, finding := range report.Findings {
			fmt.Printf("      - severity: %q\n", finding.Severity)
			fmt.Printf("        scope: %q\n", finding.Scope)
			fmt.Printf("        message: %q\n", finding.Message)
		}
	}
}

func printPromReports(reports []checker.Report) {
	fmt.Println("# HELP certops_status TLS/HTTPS aggregate status (1=current status, 0=otherwise).")
	fmt.Println("# TYPE certops_status gauge")
	fmt.Println("# HELP certops_certificate_days_remaining Days remaining until certificate expiration.")
	fmt.Println("# TYPE certops_certificate_days_remaining gauge")
	fmt.Println("# HELP certops_certificate_trusted Certificate chain trust status (1=trusted, 0=untrusted).")
	fmt.Println("# TYPE certops_certificate_trusted gauge")
	fmt.Println("# HELP certops_certificate_matches_host Certificate hostname match status (1=match, 0=mismatch).")
	fmt.Println("# TYPE certops_certificate_matches_host gauge")
	fmt.Println("# HELP certops_tls_version_supported TLS version support status (1=supported, 0=not supported).")
	fmt.Println("# TYPE certops_tls_version_supported gauge")
	fmt.Println("# HELP certops_tls_ocsp_stapling OCSP stapling status (1=present, 0=missing).")
	fmt.Println("# TYPE certops_tls_ocsp_stapling gauge")
	fmt.Println("# HELP certops_https_hsts HSTS header status (1=present, 0=missing).")
	fmt.Println("# TYPE certops_https_hsts gauge")
	fmt.Println("# HELP certops_certificate_revocation_checked Certificate CRL revocation check status (1=checked, 0=not checked).")
	fmt.Println("# TYPE certops_certificate_revocation_checked gauge")
	fmt.Println("# HELP certops_certificate_revoked Certificate revocation status (1=revoked, 0=not revoked or unchecked).")
	fmt.Println("# TYPE certops_certificate_revoked gauge")

	for _, report := range reports {
		base := map[string]string{"target": report.Target, "host": report.Host}
		for _, status := range []string{"ok", "warn", "critical", "error"} {
			fmt.Printf("certops_status{%s} %d\n", promLabels(map[string]string{
				"target": report.Target,
				"host":   report.Host,
				"status": status,
			}), boolInt(report.Status == status))
		}
		fmt.Printf("certops_certificate_days_remaining{%s} %d\n", promLabels(base), report.Certificate.DaysRemaining)
		fmt.Printf("certops_certificate_trusted{%s} %d\n", promLabels(base), boolInt(report.Certificate.Trusted))
		fmt.Printf("certops_certificate_matches_host{%s} %d\n", promLabels(base), boolInt(report.Certificate.MatchesHost))
		for _, version := range []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"} {
			fmt.Printf("certops_tls_version_supported{%s} %d\n", promLabels(map[string]string{
				"target":  report.Target,
				"host":    report.Host,
				"version": version,
			}), boolInt(hasString(report.TLS.SupportedVersions, version)))
		}
		fmt.Printf("certops_tls_ocsp_stapling{%s} %d\n", promLabels(base), boolInt(report.TLS.OCSPStapling))
		fmt.Printf("certops_https_hsts{%s} %d\n", promLabels(base), boolInt(strings.TrimSpace(report.HTTPS.HSTS) != ""))
		fmt.Printf("certops_certificate_revocation_checked{%s} %d\n", promLabels(base), boolInt(report.Revocation.Checked))
		fmt.Printf("certops_certificate_revoked{%s} %d\n", promLabels(base), boolInt(report.Revocation.Revoked))
	}
}

func promLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key, value := range labels {
		if strings.TrimSpace(value) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return strings.Join(parts, ",")
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
