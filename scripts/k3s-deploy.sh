#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v k3s >/dev/null; then echo 'Install a supported single-node k3s first: https://docs.k3s.io/quick-start'; exit 1; fi
if ! command -v docker >/dev/null; then echo 'Docker is required to build and import the local lab image'; exit 1; fi
bash scripts/generate-env.sh
if docker info >/dev/null 2>&1; then d=(docker); else d=(sudo docker); fi
sudo k3s kubectl apply -f k8s/00-core.yaml
key="$(sed -n 's/^CROWDSEC_BOUNCER_KEY=//p' .env | head -1)"
if [[ -z "$key" ]]; then echo 'Missing CROWDSEC_BOUNCER_KEY'; exit 1; fi
sudo k3s kubectl -n cloudshield create secret generic cloudshield-key --from-literal=key="$key" --dry-run=client -o yaml | sudo k3s kubectl apply -f -
sudo k3s kubectl -n cloudshield create configmap grafana-provisioning \
 --from-file=prometheus.yaml=config/grafana/provisioning/datasources/prometheus.yaml \
 --from-file=provider.yaml=config/grafana/provisioning/dashboards/provider.yaml \
 --dry-run=client -o yaml | sudo k3s kubectl apply -f -
sudo k3s kubectl -n cloudshield create configmap grafana-dashboard \
 --from-file=config/grafana/dashboards/cloudshield.json --dry-run=client -o yaml | sudo k3s kubectl apply -f -
"${d[@]}" build -f app/Dockerfile -t cloudshield-lab:1.0.0 .
"${d[@]}" save cloudshield-lab:1.0.0 | sudo k3s ctr images import -
sudo k3s kubectl apply -f k8s/10-monitoring.yaml -f k8s/20-security.yaml
sudo k3s kubectl -n cloudshield rollout status deployment/labapp --timeout=180s
sudo k3s kubectl -n cloudshield rollout status deployment/waf --timeout=180s
sudo k3s kubectl -n cloudshield get pods
printf '\nKubernetes ready. Start a localhost-only port-forward in an ECS shell:\n'
echo '  sudo k3s kubectl -n cloudshield port-forward --address 127.0.0.1 svc/waf 8080:8080'
echo 'On your own workstation: ssh -L 8080:127.0.0.1:8080 ubuntu@ECS_PUBLIC_IP'
echo 'Then open http://localhost:8080/'
echo 'Optional: sudo k3s kubectl apply -f k8s/30-antivirus.yaml'
