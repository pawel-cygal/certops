package verify

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	checker "certops/internal/check"

	"gopkg.in/yaml.v3"
)

type Spec struct {
	Defaults Defaults `yaml:"defaults" json:"defaults"`
	Targets  []Target `yaml:"targets" json:"targets"`
}

type Defaults struct {
	WarnDays     int    `yaml:"warn_days" json:"warn_days"`
	CriticalDays int    `yaml:"critical_days" json:"critical_days"`
	Timeout      string `yaml:"timeout" json:"timeout"`
	CABundle     string `yaml:"ca_bundle" json:"ca_bundle"`
}

type Target struct {
	Name             string   `yaml:"name" json:"name"`
	Host             string   `yaml:"host" json:"host"`
	Port             string   `yaml:"port" json:"port"`
	URL              string   `yaml:"url" json:"url"`
	MinDaysRemaining int      `yaml:"min_days_remaining" json:"min_days_remaining"`
	RequireTLS13     bool     `yaml:"require_tls13" json:"require_tls13"`
	RequireHSTS      bool     `yaml:"require_hsts" json:"require_hsts"`
	ForbidTLS10      bool     `yaml:"forbid_tls10" json:"forbid_tls10"`
	ForbidTLS11      bool     `yaml:"forbid_tls11" json:"forbid_tls11"`
	ExpectedNames    []string `yaml:"expected_names" json:"expected_names"`
	AllowedIssuers   []string `yaml:"allowed_issuers" json:"allowed_issuers"`
	CABundle         string   `yaml:"ca_bundle" json:"ca_bundle"`
}

type CheckFinding struct {
	Severity string `json:"severity" yaml:"severity"`
	Scope    string `json:"scope" yaml:"scope"`
	Message  string `json:"message" yaml:"message"`
}

type TargetResult struct {
	Name     string            `json:"name" yaml:"name"`
	Target   string            `json:"target" yaml:"target"`
	Status   string            `json:"status" yaml:"status"`
	Report   checker.Report    `json:"report" yaml:"report"`
	Findings []CheckFinding    `json:"findings,omitempty" yaml:"findings,omitempty"`
	Error    string            `json:"error,omitempty" yaml:"error,omitempty"`
	Meta     map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
}

type Report struct {
	File    string         `json:"file" yaml:"file"`
	Results []TargetResult `json:"results" yaml:"results"`
	Matched int            `json:"matched" yaml:"matched"`
	Total   int            `json:"total" yaml:"total"`
	Errors  int            `json:"errors" yaml:"errors"`
}

func Load(path string) (Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, err
	}
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return Spec{}, err
	}
	if len(spec.Targets) == 0 {
		return Spec{}, fmt.Errorf("spec has no targets")
	}
	for i, target := range spec.Targets {
		if err := validateTarget(target); err != nil {
			return Spec{}, fmt.Errorf("targets[%d]: %w", i, err)
		}
	}
	return spec, nil
}

func Run(ctx context.Context, file string, spec Spec, normalize func(string) (string, string, error)) Report {
	report := Report{
		File:    file,
		Total:   len(spec.Targets),
		Results: make([]TargetResult, 0, len(spec.Targets)),
	}
	timeout := 10 * time.Second
	if strings.TrimSpace(spec.Defaults.Timeout) != "" {
		if parsed, err := time.ParseDuration(spec.Defaults.Timeout); err == nil {
			timeout = parsed
		}
	}
	for _, target := range spec.Targets {
		targetString := targetString(target)
		result := TargetResult{
			Name:   targetName(target),
			Target: targetString,
		}
		host, address, err := normalize(targetString)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
			report.Errors++
			report.Results = append(report.Results, result)
			continue
		}
		caBundle := firstNonEmpty(target.CABundle, spec.Defaults.CABundle)
		checkReport := checker.Run(ctx, host, address, checker.Options{
			WarnDays:     defaultInt(spec.Defaults.WarnDays, 30),
			CriticalDays: defaultInt(spec.Defaults.CriticalDays, 14),
			Timeout:      timeout,
			CABundle:     caBundle,
		})
		result.Report = checkReport
		result.Findings = evaluateTarget(target, checkReport)
		result.Status = aggregateStatus(checkReport.Status, result.Findings)
		if result.Status == "ok" {
			report.Matched++
		} else {
			report.Errors++
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func validateTarget(target Target) error {
	if strings.TrimSpace(target.URL) == "" && strings.TrimSpace(target.Host) == "" {
		return fmt.Errorf("host or url is required")
	}
	if target.URL != "" && target.Host != "" {
		return fmt.Errorf("host and url are mutually exclusive")
	}
	return nil
}

func evaluateTarget(target Target, report checker.Report) []CheckFinding {
	var findings []CheckFinding
	for _, finding := range report.Findings {
		findings = append(findings, CheckFinding(finding))
	}
	if target.MinDaysRemaining > 0 && report.Certificate.DaysRemaining < target.MinDaysRemaining {
		findings = append(findings, CheckFinding{
			Severity: "critical",
			Scope:    "policy",
			Message:  fmt.Sprintf("certificate has %d days remaining, expected at least %d", report.Certificate.DaysRemaining, target.MinDaysRemaining),
		})
	}
	if target.RequireTLS13 && !hasString(report.TLS.SupportedVersions, "TLS1.3") {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "TLS 1.3 is required but not supported"})
	}
	if target.RequireHSTS && strings.TrimSpace(report.HTTPS.HSTS) == "" {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "HSTS is required but missing"})
	}
	if target.ForbidTLS10 && hasString(report.TLS.SupportedVersions, "TLS1.0") {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "TLS 1.0 is forbidden but supported"})
	}
	if target.ForbidTLS11 && hasString(report.TLS.SupportedVersions, "TLS1.1") {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "TLS 1.1 is forbidden but supported"})
	}
	for _, name := range target.ExpectedNames {
		if !hasString(report.Certificate.DNSNames, name) {
			findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "expected DNS name missing from SAN: " + name})
		}
	}
	if len(target.AllowedIssuers) > 0 && !containsAnyFold(report.Certificate.Issuer, target.AllowedIssuers) {
		findings = append(findings, CheckFinding{Severity: "critical", Scope: "policy", Message: "issuer is not allowed: " + report.Certificate.Issuer})
	}
	return findings
}

func targetString(target Target) string {
	if strings.TrimSpace(target.URL) != "" {
		return target.URL
	}
	host := strings.TrimSpace(target.Host)
	if target.Port != "" && !strings.Contains(host, ":") {
		return host + ":" + strings.TrimSpace(target.Port)
	}
	return host
}

func targetName(target Target) string {
	if strings.TrimSpace(target.Name) != "" {
		return target.Name
	}
	return targetString(target)
}

func aggregateStatus(base string, findings []CheckFinding) string {
	status := base
	if status == "" {
		status = "ok"
	}
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			return "critical"
		case "warn":
			if status == "ok" {
				status = "warn"
			}
		}
	}
	return status
}

func defaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsAnyFold(value string, wants []string) bool {
	value = strings.ToLower(value)
	for _, want := range wants {
		if strings.Contains(value, strings.ToLower(strings.TrimSpace(want))) {
			return true
		}
	}
	return false
}
