#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then exit 0; fi
command -v openssl >/dev/null || { echo 'Missing openssl; sudo apt-get install -y openssl'; exit 1; }
key="$(openssl rand -hex 32)"
pwd="$(openssl rand -hex 20)"
cat > .env <<EOF
LAB_BIND_IP=127.0.0.1
LAB_PORT=8080
MAX_VUS=40
MAX_SECONDS=180
CROWDSEC_BOUNCER_KEY=$key
GRAFANA_ADMIN_PASSWORD=$pwd
EOF
chmod 600 .env
echo 'Generated per-deployment .env with random keys (chmod 600).'
