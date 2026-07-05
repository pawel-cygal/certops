# certops

`certops` is a PKI and TLS operations CLI. It checks CA providers, endpoint
certificates, local trust stores, and remote Linux trust stores from one
terminal tool.

The main workflow is config-driven:

```bash
certops init
certops plan -f certops.yaml
certops plan -f certops.yaml --live
certops drift -f certops.yaml --fail-on warn
certops fleet trust plan -f certops.yaml --limit runners
certops fleet trust apply -f certops.yaml --limit runner-01 --yes
certops fleet trust verify -f certops.yaml --limit runner-01
```

`plan`, `drift`, `check`, `scan`, `verify`, and provider inspection commands
only report state. Commands that change trust stores require explicit `--yes`.

## Features

- Declarative `certops.yaml` with CA providers, inventory, trust targets, and services.
- CA provider checks for Smallstep, Vault PKI, CFSSL-compatible APIs, and generic PEM bundles or URLs.
- TLS endpoint checks for expiry, SAN/hostname match, chain trust, TLS versions, ALPN, OCSP stapling, redirects, and HSTS.
- Drift reports that compare configured PKI state with live CA and service checks.
- Local trust-store plan, verify, and install for CA bundles.
- Remote Linux trust-store plan, apply, verify, and remove over SSH.
- JSON, YAML, Prometheus text, HTML reports, and OTLP/HTTP metric export where supported.
- Watch mode for `check` and `verify`.

## Install

```bash
git clone https://github.com/pawel-cygal/certops.git
cd certops
go build -o certops .
sudo install -m 0755 certops /usr/local/bin/certops
```

For a local build without VCS metadata:

```bash
go build -buildvcs=false -o certops .
```

## Configuration

Create a starter config:

```bash
certops init
```

Example `certops.yaml`:

```yaml
policy:
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
          port: "22"
          identity_file: ~/.ssh/id_ed25519
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
```

## Core Commands

### Inventory

```bash
certops inventory list -f certops.yaml
certops inventory show runners -f certops.yaml
certops inventory show runner-01 -f certops.yaml --json
```

### CA Providers

List and fetch CAs from config:

```bash
certops ca list -f certops.yaml
certops ca fetch -f certops.yaml --out roots/
```

Check providers directly:

```bash
certops ca smallstep health --url https://ca.lan.example.com
certops ca smallstep roots --url https://ca.lan.example.com --fingerprint SHA256:AA:BB:... --out smallstep-roots.pem
certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint SHA256:AA:BB:... --insecure

certops ca vault health --url http://127.0.0.1:8200
certops ca vault ca --url http://127.0.0.1:8200 --mount pki --out vault-ca.pem
certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint SHA256:AA:BB:...

certops ca cfssl health --url http://127.0.0.1:8888
certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint SHA256:AA:BB:... --out cfssl-ca.pem

certops ca generic info --ca-bundle vendor-root.pem
certops ca generic info --url https://pki.example.com/root.pem --fingerprint SHA256:AA:BB:... --out vendor-root.pem
```

Use `--fingerprint` when fetching CA material from a URL. `--insecure` exists
for bootstrap cases where the CA HTTPS endpoint is not trusted yet; pin the
fingerprint in the same command.

### Plan And Drift

```bash
certops plan -f certops.yaml
certops plan -f certops.yaml --live
certops plan -f certops.yaml --html certops-plan.html
certops drift -f certops.yaml
certops drift -f certops.yaml --fail-on warn
certops drift -f certops.yaml --no-live
certops drift -f certops.yaml --html certops-drift.html
```

`plan` validates the configured CA providers, inventory, trust policies, and
services. With `--live`, it also fetches configured CA roots and runs live TLS
checks for configured services.

`drift` uses the same model and reports non-OK or manual items. Use `--no-live`
for static config drift only.

### Local Trust Store

```bash
certops trust plan --ca-bundle company-root.pem
certops trust verify --ca-bundle company-root.pem
certops trust plan --url https://pki.example.com/roots.pem --fingerprint SHA256:AA:BB:...
certops trust plan --smallstep-url https://ca.lan.example.com --fingerprint SHA256:AA:BB:...
sudo certops trust install --ca-bundle company-root.pem --name company-root --yes
```

`trust install` modifies the local trust store and requires `--yes`.

### Remote Fleet Trust

```bash
certops fleet trust plan -f certops.yaml
certops fleet trust plan -f certops.yaml --limit runners --html fleet-plan.html
certops fleet trust apply -f certops.yaml --limit runner-01 --yes
certops fleet trust verify -f certops.yaml --limit runner-01
certops fleet trust remove -f certops.yaml --limit runner-01 --yes
```

Remote trust operations currently target Linux hosts over SSH. `apply`,
`install`, and `remove` change the remote trust store and require `--yes`.
Managed roots are written under:

```text
/usr/local/share/ca-certificates/certops-<ca-name>.crt
```

### Endpoint Checks

```bash
certops check example.com
certops check https://api.example.com
certops check example.com:8443 --json
certops check internal.example.com --ca-bundle smallstep-root.pem
certops check api.example.com --watch --until-ok --interval 5s
certops check api.example.com --html certops-report.html
```

`check` accepts `host`, `host:port`, or `https://host`. It supports
`--json`, `--yaml`, `--prom`, `--html`, `--otel-endpoint`, `--warn-days`,
`--critical-days`, `--ca-bundle`, `--fail-on`, and watch flags.

Scan multiple targets:

```bash
certops scan --input domains.txt
certops scan example.com api.example.com --json
certops scan --input domains.txt --prom
certops scan --input domains.txt --html certops-report.html
```

### Expected-State Verification

```bash
certops verify -f certs.yaml
certops verify -f certs.yaml --json
certops verify -f certs.yaml --prom
certops verify -f certs.yaml --html certops-report.html
certops verify -f certs.yaml --watch --until-ok
```

Example `certs.yaml`:

```yaml
defaults:
  warn_days: 30
  critical_days: 14
  timeout: 10s
  ca_bundle: smallstep-root.pem

targets:
  - name: internal-api
    host: api.lan.example.com
    min_days_remaining: 30
    require_tls13: true
    require_hsts: true
    forbid_tls10: true
    forbid_tls11: true
    expected_names:
      - api.lan.example.com
    allowed_issuers:
      - Smallstep
```

## Output And Exit Codes

Supported outputs vary by command, but the common formats are:

- human-readable table or report output
- `--json`
- `--yaml`
- `--prom`
- `--html report.html`
- `--otel-endpoint http://collector:4318`

Exit codes:

- `0`: no findings at or above the selected threshold
- `1`: findings at or above `--fail-on`
- `2`: usage, config, or runtime error

## Local Lab

The repository includes a Docker-based lab for Smallstep, Vault PKI,
CFSSL-compatible APIs, generic PEM roots, a Linux SSH target, and an HTTPS test
service.

```bash
bash docs/lab/bootstrap.sh
bash docs/lab/smoke.sh
bash docs/lab/cleanup.sh
```

See [`docs/LAB.md`](docs/LAB.md).

## Development

```bash
go test ./...
go build -buildvcs=false -o /tmp/certops .
```
