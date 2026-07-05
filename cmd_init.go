package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const starterConfig = `policy:
  fail_on: warn
  min_ca_days_remaining: 180
  min_leaf_days_remaining: 30
  allow_unmanaged_roots: false

cas:
  - name: lan-step
    provider: smallstep
    url: https://ca.lan.example.com
    fingerprint: SHA256:AA:BB:...

  - name: vault-prod
    provider: vault
    url: https://vault.example.com
    mount: pki
    fingerprint: SHA256:CC:DD:...

  - name: vendor-root
    provider: generic
    ca_bundle: vendor-root.pem
    fingerprint: SHA256:11:22:...

inventory:
  groups:
    runners:
      hosts:
        runner-01:
          address: 10.10.1.21
          user: ops
          os: linux

trust:
  targets:
    - group: runners
      required:
        - lan-step

services:
  - name: internal-api
    url: https://api.lan.example.com
    ca: lan-step
    expected_names:
      - api.lan.example.com
    require_tls13: true
    require_hsts: true
`

func cmdInit(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true})
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	file := fs.String("f", "certops.yaml", "config file to create")
	force := fs.Bool("force", false, "overwrite existing config")
	fs.Parse(args)

	path := defaultConfigPath(*file)
	if !*force {
		if _, err := os.Stat(path); err == nil {
			fatal(path + " already exists; use --force to overwrite")
		}
	}
	if err := os.WriteFile(path, []byte(starterConfig), 0644); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("created %s\n", strings.TrimSpace(path))
}
