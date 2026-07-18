package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func loadConfig(path string) (certopsConfig, error) {
	if strings.TrimSpace(path) == "" {
		path = "certops.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return certopsConfig{}, err
	}
	var cfg certopsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return certopsConfig{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return certopsConfig{}, err
	}
	return cfg, nil
}

func validateConfig(cfg certopsConfig) error {
	if strings.TrimSpace(cfg.Policy.FailOn) != "" {
		switch strings.ToLower(strings.TrimSpace(cfg.Policy.FailOn)) {
		case "warn", "critical":
		default:
			return fmt.Errorf("policy fail_on must be warn or critical")
		}
	}
	seenCA := map[string]bool{}
	for _, ca := range cfg.CAs {
		if strings.TrimSpace(ca.Name) == "" {
			return fmt.Errorf("ca name is required")
		}
		if seenCA[ca.Name] {
			return fmt.Errorf("duplicate ca name: %s", ca.Name)
		}
		seenCA[ca.Name] = true
		switch strings.ToLower(strings.TrimSpace(ca.Provider)) {
		case "smallstep", "vault", "cfssl", "generic":
		default:
			return fmt.Errorf("unsupported ca provider for %s: %s", ca.Name, ca.Provider)
		}
	}
	seenCRL := map[string]bool{}
	for _, crl := range cfg.CRLs {
		if strings.TrimSpace(crl.Name) == "" {
			return fmt.Errorf("crl name is required")
		}
		if seenCRL[crl.Name] {
			return fmt.Errorf("duplicate crl name: %s", crl.Name)
		}
		seenCRL[crl.Name] = true
		if strings.TrimSpace(crl.File) == "" && strings.TrimSpace(crl.URL) == "" {
			return fmt.Errorf("crl %s requires file or url", crl.Name)
		}
		if strings.TrimSpace(crl.File) != "" && strings.TrimSpace(crl.URL) != "" {
			return fmt.Errorf("crl %s cannot define both file and url", crl.Name)
		}
		if strings.TrimSpace(crl.CA) != "" && !seenCA[crl.CA] {
			return fmt.Errorf("crl %s references unknown ca: %s", crl.Name, crl.CA)
		}
	}
	for _, service := range cfg.Services {
		for _, name := range service.CRLs {
			if !seenCRL[name] {
				target := service.Name
				if target == "" {
					target = service.URL
				}
				return fmt.Errorf("service %s references unknown crl: %s", target, name)
			}
		}
	}
	return nil
}

func defaultConfigPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "certops.yaml"
	}
	return path
}
