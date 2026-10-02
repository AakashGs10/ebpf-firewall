#!/usr/bin/env bash
# Restrict Grafana/Prometheus/metrics/upload ports to the caller's CURRENT public IP.
# Run it again whenever your network changes (for example at the college).
set -euo pipefail
RG="${RG:-eBPF-Final}"
NSG="${NSG:-$(az network nsg list -g "$RG" --query '[0].name' -o tsv)}"
MYIP="$(curl -s https://api.ipify.org)"
[[ "$MYIP" =~ ^[0-9.]+$ ]] || { echo "could not detect public IP"; exit 1; }
echo "Allowing $MYIP on $RG/$NSG"

# remove the old wide-open rules (ignored if they do not exist)
for OLD in open-port-3000 open-port-8080 open-port-9090 AllowChat AllowChatTCP AllowUpload; do
  az network nsg rule delete -g "$RG" --nsg-name "$NSG" -n "$OLD" 2>/dev/null || true
done

PRIO=210
for PORT in 3000 8000 8080 9090; do
  az network nsg rule create -g "$RG" --nsg-name "$NSG" -n "restrict-$PORT" \
    --priority "$PRIO" --direction Inbound --access Allow --protocol Tcp \
    --source-address-prefixes "$MYIP" --destination-port-ranges "$PORT" -o none
  PRIO=$((PRIO+10))
done
az network nsg rule list -g "$RG" --nsg-name "$NSG" -o table
