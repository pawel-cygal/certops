package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	checker "certops/internal/check"
	"certops/internal/verify"
)

type otelPayload struct {
	ResourceMetrics []otelResourceMetric `json:"resourceMetrics"`
}

type otelResourceMetric struct {
	Resource     otelResource      `json:"resource"`
	ScopeMetrics []otelScopeMetric `json:"scopeMetrics"`
}

type otelResource struct {
	Attributes []otelAttribute `json:"attributes"`
}

type otelScopeMetric struct {
	Scope   otelScope    `json:"scope"`
	Metrics []otelMetric `json:"metrics"`
}

type otelScope struct {
	Name string `json:"name"`
}

type otelMetric struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Unit        string    `json:"unit,omitempty"`
	Gauge       otelGauge `json:"gauge"`
}

type otelGauge struct {
	DataPoints []otelDataPoint `json:"dataPoints"`
}

type otelDataPoint struct {
	Attributes   []otelAttribute `json:"attributes,omitempty"`
	TimeUnixNano string          `json:"timeUnixNano"`
	AsInt        string          `json:"asInt"`
}

type otelAttribute struct {
	Key   string    `json:"key"`
	Value otelValue `json:"value"`
}

type otelValue struct {
	StringValue string `json:"stringValue,omitempty"`
}

func exportReportsOTEL(endpoint string, reports []checker.Report) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	metrics := make([]otelMetric, 0, len(reports)*12)
	now := time.Now()
	for _, report := range reports {
		base := map[string]string{"target": report.Target, "host": report.Host}
		for _, status := range []string{"ok", "warn", "critical", "error"} {
			metrics = append(metrics, otelMetricInt("certops.status", "TLS/HTTPS aggregate status", "", map[string]string{
				"target": report.Target,
				"host":   report.Host,
				"status": status,
			}, boolInt(report.Status == status), now))
		}
		metrics = append(metrics,
			otelMetricInt("certops.certificate.days_remaining", "Days remaining until certificate expiration", "d", base, report.Certificate.DaysRemaining, now),
			otelMetricInt("certops.certificate.trusted", "Certificate chain trust status", "", base, boolInt(report.Certificate.Trusted), now),
			otelMetricInt("certops.certificate.matches_host", "Certificate hostname match status", "", base, boolInt(report.Certificate.MatchesHost), now),
			otelMetricInt("certops.tls.ocsp_stapling", "OCSP stapling status", "", base, boolInt(report.TLS.OCSPStapling), now),
			otelMetricInt("certops.https.hsts", "HSTS header status", "", base, boolInt(strings.TrimSpace(report.HTTPS.HSTS) != ""), now),
		)
		for _, version := range []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"} {
			metrics = append(metrics, otelMetricInt("certops.tls.version_supported", "TLS version support status", "", map[string]string{
				"target":  report.Target,
				"host":    report.Host,
				"version": version,
			}, boolInt(hasString(report.TLS.SupportedVersions, version)), now))
		}
	}
	return postOTLP(endpoint, "certops", metrics)
}

func exportVerifyOTEL(endpoint string, report verify.Report) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	now := time.Now()
	metrics := make([]otelMetric, 0, len(report.Results)+3)
	for _, result := range report.Results {
		metrics = append(metrics, otelMetricInt("certops.verify.target_ok", "Certificate verification target status", "", map[string]string{
			"file":   report.File,
			"name":   result.Name,
			"target": result.Target,
		}, boolInt(result.Status == "ok"), now))
	}
	metrics = append(metrics,
		otelMetricInt("certops.verify.summary.matched", "Number of matched targets", "", map[string]string{"file": report.File}, report.Matched, now),
		otelMetricInt("certops.verify.summary.total", "Total number of targets", "", map[string]string{"file": report.File}, report.Total, now),
		otelMetricInt("certops.verify.summary.errors", "Number of failed targets", "", map[string]string{"file": report.File}, report.Errors, now),
	)
	return postOTLP(endpoint, "certops", metrics)
}

func otelMetricInt(name, description, unit string, labels map[string]string, value int, ts time.Time) otelMetric {
	return otelMetric{
		Name:        name,
		Description: description,
		Unit:        unit,
		Gauge: otelGauge{DataPoints: []otelDataPoint{{
			Attributes:   otelAttributes(labels),
			TimeUnixNano: fmt.Sprintf("%d", ts.UnixNano()),
			AsInt:        fmt.Sprintf("%d", value),
		}}},
	}
}

func otelAttributes(labels map[string]string) []otelAttribute {
	out := make([]otelAttribute, 0, len(labels))
	for key, value := range labels {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, otelAttribute{Key: key, Value: otelValue{StringValue: value}})
	}
	return out
}

func postOTLP(endpoint, service string, metrics []otelMetric) error {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if !strings.HasSuffix(endpoint, "/v1/metrics") {
		endpoint += "/v1/metrics"
	}
	payload := otelPayload{ResourceMetrics: []otelResourceMetric{{
		Resource: otelResource{Attributes: []otelAttribute{
			{Key: "service.name", Value: otelValue{StringValue: service}},
		}},
		ScopeMetrics: []otelScopeMetric{{
			Scope:   otelScope{Name: service},
			Metrics: metrics,
		}},
	}}}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otel export failed: %s", resp.Status)
	}
	return nil
}
