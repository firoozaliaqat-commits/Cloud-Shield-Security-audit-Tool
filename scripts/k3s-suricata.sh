#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sudo k3s kubectl -n cloudshield create configmap suricata-case \
  --from-file=config/suricata/lab-demo.pcap --from-file=config/suricata/lab.rules \
  --dry-run=client -o yaml | sudo k3s kubectl apply -f -
sudo k3s kubectl -n cloudshield delete job suricata-demo --ignore-not-found
sudo k3s kubectl apply -f k8s/40-ids-job.yaml
sudo k3s kubectl -n cloudshield wait --for=condition=complete job/suricata-demo --timeout=180s
sudo k3s kubectl -n cloudshield logs job/suricata-demo --tail=25
echo 'Inspect /api/ids/alerts for Suricata signatures.'
