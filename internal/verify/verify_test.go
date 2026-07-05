package verify

import (
	"strings"
	"testing"

	checker "certops/internal/check"
)

func TestEvaluateTargetPolicyFindings(t *testing.T) {
	target := Target{
		MinDaysRemaining: 30,
		RequireTLS13:     true,
		RequireHSTS:      true,
		ForbidTLS10:      true,
		ExpectedNames:    []string{"api.example.com"},
		AllowedIssuers:   []string{"Smallstep"},
	}
	report := checker.Report{
		Status: "ok",
		Certificate: checker.Certificate{
			DaysRemaining: 12,
			DNSNames:      []string{"www.example.com"},
			Issuer:        "CN=Other CA",
		},
		TLS: checker.TLSInfo{
			SupportedVersions: []string{"TLS1.0", "TLS1.2"},
		},
		HTTPS: checker.HTTPSInfo{},
	}

	findings := evaluateTarget(target, report)
	joined := findingMessages(findings)
	for _, want := range []string{
		"expected at least 30",
		"TLS 1.3 is required",
		"HSTS is required",
		"TLS 1.0 is forbidden",
		"expected DNS name missing",
		"issuer is not allowed",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing finding containing %q in:\n%s", want, joined)
		}
	}
}

func TestAggregateStatus(t *testing.T) {
	if got := aggregateStatus("ok", nil); got != "ok" {
		t.Fatalf("status = %q, want ok", got)
	}
	if got := aggregateStatus("ok", []CheckFinding{{Severity: "warn"}}); got != "warn" {
		t.Fatalf("status = %q, want warn", got)
	}
	if got := aggregateStatus("warn", []CheckFinding{{Severity: "critical"}}); got != "critical" {
		t.Fatalf("status = %q, want critical", got)
	}
}

func findingMessages(findings []CheckFinding) string {
	var out []string
	for _, finding := range findings {
		out = append(out, finding.Message)
	}
	return strings.Join(out, "\n")
}
