package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"strings"
	"time"

	checker "certops/internal/check"
)

func cmdScan(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--input": true, "--warn-days": true, "--critical-days": true, "--ca-bundle": true, "--fail-on": true, "--timeout": true, "--html": true, "--otel-endpoint": true})
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	input := fs.String("input", "", "input file with one host/url per line")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML-like output")
	promOut := fs.Bool("prom", false, "emit Prometheus text output")
	htmlOut := fs.String("html", "", "write HTML report to path")
	otelEndpoint := fs.String("otel-endpoint", "", "export OTLP/HTTP metrics to endpoint, for example http://localhost:4318")
	warnDays := fs.Int("warn-days", 30, "warning threshold for certificate expiry")
	criticalDays := fs.Int("critical-days", 14, "critical threshold for certificate expiry")
	caBundle := fs.String("ca-bundle", "", "PEM root/intermediate CA bundle used for additional trust validation")
	failOn := fs.String("fail-on", "critical", "exit non-zero on warn or critical")
	timeout := fs.Duration("timeout", 10*time.Second, "network timeout")
	fs.Parse(args)

	targets := append([]string(nil), fs.Args()...)
	if *input != "" {
		rows, err := readInput(*input)
		if err != nil {
			fatal(err.Error())
		}
		targets = append(targets, rows...)
	}
	if len(targets) == 0 {
		fatal("usage: certops scan --input domains.txt [--json|--yaml|--prom]")
	}
	format, err := resolveOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}

	reports := make([]checker.Report, 0, len(targets))
	for _, target := range targets {
		host, address, err := normalizeTarget(target)
		if err != nil {
			reports = append(reports, checker.Report{
				Target: target,
				Host:   target,
				Status: "error",
				Error:  err.Error(),
			})
			continue
		}
		reports = append(reports, checker.Run(context.Background(), host, address, checker.Options{
			WarnDays:     *warnDays,
			CriticalDays: *criticalDays,
			Timeout:      *timeout,
			CABundle:     *caBundle,
		}))
	}
	if strings.TrimSpace(*htmlOut) != "" {
		if err := writeReportsHTML(*htmlOut, "certops scan", reports); err != nil {
			fatal(err.Error())
		}
	}
	if err := exportReportsOTEL(*otelEndpoint, reports); err != nil {
		fatal(err.Error())
	}
	printReports(reports, format)
	os.Exit(exitForReports(reports, *failOn))
}

func readInput(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
