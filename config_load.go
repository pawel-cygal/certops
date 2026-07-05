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
	return nil
}

func defaultConfigPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "certops.yaml"
	}
	return path
}
