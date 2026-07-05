package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	checker "certops/internal/check"
)

func livePlanItems(cfg certopsConfig, opts planOptions) []planItem {
	items := []planItem{}
	rootDir, err := os.MkdirTemp("", "certops-plan-roots-*")
	if err != nil {
		return []planItem{{Action: "fail", Scope: "live", Target: "roots", Status: "critical", Change: "could not create temporary root directory", Actual: err.Error()}}
	}
	defer os.RemoveAll(rootDir)

	rootPaths := map[string]string{}
	for _, ca := range cfg.CAs {
		item, path := liveCAPlanItem(ca, rootDir)
		items = append(items, item)
		if path != "" {
			rootPaths[ca.Name] = path
		}
	}
	for _, service := range cfg.Services {
		items = append(items, liveServicePlanItem(service, cfg, rootPaths, opts.Timeout))
	}
	return items
}

func liveCAPlanItem(ca configCA, rootDir string) (planItem, string) {
	item := planItem{Action: "verify", Scope: "ca-live", Target: ca.Name, Status: "ok"}
	pemData, count, err := configuredCAPEM(ca)
	if err != nil {
		item.Status = "critical"
		item.Change = "CA live check failed"
		item.Actual = err.Error()
		return item, ""
	}
	path := filepath.Join(rootDir, sanitizeTrustName(ca.Name)+".pem")
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		item.Status = "critical"
		item.Change = "CA live check could not write temporary bundle"
		item.Actual = err.Error()
		return item, ""
	}
	item.Change = fmt.Sprintf("CA live check ok, fetched %d certs", count)
	item.Actual = "temporary bundle fetched"
	return item, path
}

func liveServicePlanItem(service configService, cfg certopsConfig, rootPaths map[string]string, timeout time.Duration) planItem {
	targetName := servicePlanTarget(service)
	item := planItem{Action: "verify", Scope: "service-live", Target: targetName, Status: "ok"}
	target, err := serviceCheckTarget(service, cfg)
	if err != nil {
		item.Status = "critical"
		item.Change = "service live check target is invalid"
		item.Actual = err.Error()
		return item
	}
	host, address, err := normalizeTarget(target)
	if err != nil {
		item.Status = "critical"
		item.Change = "service live check target is invalid"
		item.Actual = err.Error()
		return item
	}
	report := checker.Run(context.Background(), host, address, checker.Options{
		WarnDays:     policyWarnDays(cfg),
		CriticalDays: 14,
		Timeout:      timeout,
		CABundle:     rootPaths[service.CA],
	})
	item.Status = planStatusFromCheckStatus(report.Status)
	item.Change = fmt.Sprintf("service live check %s", report.Status)
	item.Actual = liveServiceActual(report)
	return item
}

func servicePlanTarget(service configService) string {
	if service.Name != "" {
		return service.Name
	}
	if service.URL != "" {
		return service.URL
	}
	return service.Host
}

func serviceCheckTarget(service configService, cfg certopsConfig) (string, error) {
	if strings.TrimSpace(service.URL) != "" {
		return service.URL, nil
	}
	if strings.TrimSpace(service.Host) == "" {
		return "", fmt.Errorf("service has no url or host")
	}
	host := service.Host
	if inventoryHost, ok := findInventoryHost(cfg, service.Host); ok {
		host = inventoryHost.Address
	}
	if service.Port != "" {
		return net.JoinHostPort(host, service.Port), nil
	}
	return host, nil
}

func findInventoryHost(cfg certopsConfig, name string) (configHost, bool) {
	for _, group := range cfg.Inventory.Groups {
		if host, ok := group.Hosts[name]; ok {
			return host, true
		}
	}
	return configHost{}, false
}

func policyWarnDays(cfg certopsConfig) int {
	if cfg.Policy.MinLeafDaysRemaining > 0 {
		return cfg.Policy.MinLeafDaysRemaining
	}
	return 30
}

func planStatusFromCheckStatus(status string) string {
	switch status {
	case "ok", "warn":
		return status
	default:
		return "critical"
	}
}

func liveServiceActual(report checker.Report) string {
	if report.Error != "" {
		return report.Error
	}
	return fmt.Sprintf("issuer=%s expires_in=%d days", shortIssuer(report.Certificate.Issuer), report.Certificate.DaysRemaining)
}
