#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$LAB_DIR/.state"
HTTPS_DIR="$STATE_DIR/https-vault"
CFSSL_DIR="$STATE_DIR/cfssl"
TARGET_SSH_DIR="$LAB_DIR/target/ssh"
PASSWORD_FILE="$LAB_DIR/step-password.txt"

mkdir -p "$STATE_DIR" "$HTTPS_DIR" "$CFSSL_DIR" "$TARGET_SSH_DIR" "$LAB_DIR/generic-roots"

if [[ ! -f "$STATE_DIR/id_ed25519" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$STATE_DIR/id_ed25519" -C certops-lab >/dev/null
fi
cp "$STATE_DIR/id_ed25519.pub" "$TARGET_SSH_DIR/authorized_keys"

if [[ ! -f "$PASSWORD_FILE" ]]; then
  printf 'certops-lab-password\n' > "$PASSWORD_FILE"
  chmod 0600 "$PASSWORD_FILE"
fi

cd "$LAB_DIR"
docker compose up -d --build step-ca vault target-linux

wait_http() {
  local name="$1"
  local url="$2"
  local curl_args="${3:-}"

  printf 'waiting for %s' "$name"
  for _ in $(seq 1 60); do
    if curl -fsS $curl_args "$url" >/dev/null 2>&1; then
      printf '\n'
      return 0
    fi
    printf '.'
    sleep 1
  done
  printf '\n'
  printf 'timeout waiting for %s at %s\n' "$name" "$url" >&2
  return 1
}

wait_http "Smallstep" "https://127.0.0.1:9000/health" "-k"
wait_http "Vault" "http://127.0.0.1:8200/v1/sys/health"

docker exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=root \
  certops-vault vault secrets enable pki >/dev/null 2>&1 || true
docker exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=root \
  certops-vault vault secrets tune -max-lease-ttl=87600h pki >/dev/null
if ! docker exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=root \
  certops-vault vault read pki/cert/ca >/dev/null 2>&1; then
  docker exec \
    -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e VAULT_TOKEN=root \
    certops-vault vault write -field=certificate pki/root/generate/internal \
      common_name="Certops Lab Vault Root" ttl=87600h > "$STATE_DIR/vault-root.pem"
fi

docker exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=root \
  certops-vault vault write pki/roles/lab-server \
    allowed_domains=localhost allow_bare_domains=true allow_ip_sans=true max_ttl=24h >/dev/null
docker exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=root \
  certops-vault vault write -format=json pki/issue/lab-server \
    common_name=localhost ip_sans=127.0.0.1 ttl=24h > "$HTTPS_DIR/issue.json"
python3 - "$HTTPS_DIR/issue.json" "$HTTPS_DIR" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
out = pathlib.Path(sys.argv[2])
data = payload["data"]
(out / "cert.pem").write_text(data["certificate"] + "\n")
(out / "key.pem").write_text(data["private_key"] + "\n")
(out / "issuing_ca.pem").write_text(data["issuing_ca"] + "\n")
(out / "fullchain.pem").write_text(data["certificate"] + "\n" + data["issuing_ca"] + "\n")
PY

docker cp certops-step-ca:/home/step/certs/root_ca.crt "$STATE_DIR/smallstep-root.pem"
certops ca vault ca --url http://127.0.0.1:8200 --mount pki --out "$STATE_DIR/vault-root.pem" >/dev/null
cp "$STATE_DIR/vault-root.pem" "$CFSSL_DIR/root.pem"
cp "$STATE_DIR/smallstep-root.pem" "$LAB_DIR/generic-roots/generic-root.pem"
chmod 0644 "$CFSSL_DIR/root.pem" "$LAB_DIR/generic-roots/generic-root.pem"

smallstep_fp="$(openssl x509 -in "$STATE_DIR/smallstep-root.pem" -noout -fingerprint -sha256 | sed 's/^.*=//; s/^/SHA256:/')"
vault_fp="$(openssl x509 -in "$STATE_DIR/vault-root.pem" -noout -fingerprint -sha256 | sed 's/^.*=//; s/^/SHA256:/')"
cfssl_fp="$(openssl x509 -in "$CFSSL_DIR/root.pem" -noout -fingerprint -sha256 | sed 's/^.*=//; s/^/SHA256:/')"
generic_fp="$(openssl x509 -in "$LAB_DIR/generic-roots/generic-root.pem" -noout -fingerprint -sha256 | sed 's/^.*=//; s/^/SHA256:/')"

cat > "$LAB_DIR/certops.lab.yaml" <<EOF
policy:
  fail_on: warn
  min_ca_days_remaining: 180
  min_leaf_days_remaining: 30
  allow_unmanaged_roots: false

cas:
  - name: lab-smallstep
    provider: smallstep
    url: https://127.0.0.1:9000
    fingerprint: $smallstep_fp
    insecure: true

  - name: lab-vault
    provider: vault
    url: http://127.0.0.1:8200
    mount: pki
    fingerprint: $vault_fp

  - name: lab-cfssl
    provider: cfssl
    url: http://127.0.0.1:8888
    fingerprint: $cfssl_fp

  - name: lab-generic-file
    provider: generic
    ca_bundle: $LAB_DIR/generic-roots/generic-root.pem
    fingerprint: $generic_fp

  - name: lab-generic-url
    provider: generic
    url: http://127.0.0.1:8088/generic-root.pem
    fingerprint: $generic_fp

inventory:
  groups:
    lab:
      hosts:
        target-linux:
          address: 127.0.0.1
          user: ops
          port: "2222"
          identity_file: "$STATE_DIR/id_ed25519"
          os: linux

trust:
  targets:
    - host: target-linux
      required:
        - lab-smallstep
        - lab-vault
        - lab-cfssl
        - lab-generic-file
        - lab-generic-url

services: []
EOF

docker compose up -d https-vault cfssl-mock generic-roots
wait_http "Vault HTTPS service" "https://127.0.0.1:9443" "-k"
wait_http "CFSSL mock" "http://127.0.0.1:8888/api/v1/cfssl/health"
wait_http "Generic roots" "http://127.0.0.1:8088/generic-root.pem"

certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint "$smallstep_fp" --insecure >/dev/null
certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint "$vault_fp" >/dev/null
certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint "$cfssl_fp" >/dev/null
certops ca generic info --ca-bundle "$LAB_DIR/generic-roots/generic-root.pem" --fingerprint "$generic_fp" >/dev/null
certops ca generic info --url http://127.0.0.1:8088/generic-root.pem --fingerprint "$generic_fp" >/dev/null
certops ca fetch -f "$LAB_DIR/certops.lab.yaml" --out "$STATE_DIR/roots" >/dev/null

cat <<EOF
certops lab is ready

Config:
  $LAB_DIR/certops.lab.yaml

Roots:
  $STATE_DIR/roots

Try:
  certops ca smallstep info --url https://127.0.0.1:9000 --fingerprint "$smallstep_fp" --insecure
  certops ca vault info --url http://127.0.0.1:8200 --mount pki --fingerprint "$vault_fp"
  certops ca cfssl info --url http://127.0.0.1:8888 --fingerprint "$cfssl_fp"
  certops ca generic info --url http://127.0.0.1:8088/generic-root.pem --fingerprint "$generic_fp"
  certops ca fetch -f docs/lab/certops.lab.yaml --out /tmp/certops-lab-roots
  certops inventory list -f docs/lab/certops.lab.yaml
  certops plan -f docs/lab/certops.lab.yaml --live
  certops drift -f docs/lab/certops.lab.yaml --no-live
  ssh -i docs/lab/.state/id_ed25519 -p 2222 ops@127.0.0.1

Cleanup:
  bash docs/lab/cleanup.sh
EOF
