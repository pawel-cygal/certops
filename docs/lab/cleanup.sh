#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$LAB_DIR"
docker compose down -v

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "$LAB_DIR/.state"
  rm -f "$LAB_DIR/certops.lab.yaml"
  rm -f "$LAB_DIR/step-password.txt"
  rm -f "$LAB_DIR/target/ssh/authorized_keys"
  rm -f "$LAB_DIR/generic-roots/"*.pem
fi

cat <<EOF
certops lab containers and volumes removed.
EOF

if [[ "${1:-}" == "--purge" ]]; then
  cat <<EOF
Generated local lab files were removed.
EOF
else
  cat <<EOF
Local generated files are still present under:
  $LAB_DIR/.state
  $LAB_DIR/certops.lab.yaml

Run with --purge if you want a completely fresh bootstrap.
EOF
fi
