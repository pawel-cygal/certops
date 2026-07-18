package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type outputFormat string

const (
	outputRaw  outputFormat = "raw"
	outputJSON outputFormat = "json"
	outputYAML outputFormat = "yaml"
	outputProm outputFormat = "prom"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*f = append(*f, part)
		}
	}
	return nil
}

func resolveOutput(jsonOut, yamlOut, promOut bool) (outputFormat, error) {
	n := 0
	for _, enabled := range []bool{jsonOut, yamlOut, promOut} {
		if enabled {
			n++
		}
	}
	if n > 1 {
		return "", fmt.Errorf("--json, --yaml and --prom are mutually exclusive")
	}
	switch {
	case jsonOut:
		return outputJSON, nil
	case yamlOut:
		return outputYAML, nil
	case promOut:
		return outputProm, nil
	default:
		return outputRaw, nil
	}
}

// normalizeFlagArgs moves recognized flags (and their values, when separate)
// ahead of positional args so stdlib flag.FlagSet accepts a human CLI:
// `certops check example.com --json` becomes `certops check --json example.com`.
func normalizeFlagArgs(args []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			if valueFlags[arg] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, arg)
	}
	return append(flags, pos...)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}

func printYAMLValue(v any) {
	enc := yaml.NewEncoder(os.Stdout)
	defer enc.Close()
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}

func normalizeTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("target is required")
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", err
		}
		if u.Hostname() == "" {
			return "", "", fmt.Errorf("url has no hostname")
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return u.Hostname(), net.JoinHostPort(u.Hostname(), port), nil
	}

	host := raw
	port := "443"
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host = h
		port = p
	} else if strings.Count(raw, ":") == 1 {
		parts := strings.Split(raw, ":")
		if _, err := strconv.Atoi(parts[1]); err == nil {
			host = parts[0]
			port = parts[1]
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", "", fmt.Errorf("target has no hostname")
	}
	return host, net.JoinHostPort(host, port), nil
}

func boolInt(ok bool) int {
	if ok {
		return 1
	}
	return 0
}
