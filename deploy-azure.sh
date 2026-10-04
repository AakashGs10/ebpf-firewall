#!/bin/bash
# =============================================================
# Azure Deployment Script for eBPF Cloud Firewall
# Provisions an Azure VM (Student Free Tier) and deploys
# the full eBPF defense array + telemetry stack
# =============================================================
set -e

# ---- CONFIGURATION ----
RESOURCE_GROUP="eBPF-Cloud-Defense"
VM_NAME="ebpf-shield-node"
LOCATION="eastasia"
VM_SIZE="Standard_B1s"
VM_IMAGE="Ubuntu2204"
ADMIN_USER="azureuser"
REPO_URL="https://github.com/AakashGs10/ebpf-firewall.git"

echo "=============================================="
echo " eBPF Cloud Firewall - Azure Deployment"
echo "=============================================="

# ---- PHASE 1: AZURE AUTHENTICATION ----
echo ""
echo "[PHASE 1] Authenticating with Azure..."
# Use simple az login; if it prompts for a browser, follow it.
az login >/dev/null
echo "[PHASE 1] Authentication successful."

# ---- PHASE 1.5: CLEANUP PREVIOUS DEPLOYMENT ----
echo ""
echo "[PHASE 1.5] Checking for previous deployments..."
EXISTS=$(az group exists --name "$RESOURCE_GROUP" --output tsv || echo "false")
if [ "$EXISTS" = "true" ]; then
  echo "Found existing resource group '$RESOURCE_GROUP'. Deleting it now..."
  echo "This might take a few minutes. Please wait..."
  az group delete --name "$RESOURCE_GROUP" --yes
  echo "Cleanup complete."
else
  echo "No previous deployment found."
fi

# ---- PHASE 2: RESOURCE GROUP ----
echo ""
echo "[PHASE 2] Creating Resource Group: $RESOURCE_GROUP in $LOCATION..."
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output table

# ---- PHASE 3: PROVISION THE VIRTUAL MACHINE ----
echo ""
echo "[PHASE 3] Provisioning Ubuntu 22.04 VM ($VM_SIZE - Free Tier)..."
VM_OUTPUT=$(az vm create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --image "$VM_IMAGE" \
  --size "$VM_SIZE" \
  --admin-username "$ADMIN_USER" \
  --generate-ssh-keys \
  --output json)

# Extract the public IP
PUBLIC_IP=$(echo "$VM_OUTPUT" | grep -oP '"publicIpAddress":\s*"\K[^"]+')
echo "[PHASE 3] VM provisioned. Public IP: $PUBLIC_IP"

# ---- PHASE 4: OPEN NETWORK SECURITY GROUP PORTS ----
echo ""
echo "[PHASE 4] Configuring Azure NSG firewall rules..."

# Port 8080: Prometheus metrics exporter
az vm open-port --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --port 8080 --priority 100 --output none
# Port 3000: Grafana dashboard
az vm open-port --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --port 3000 --priority 110 --output none
# Port 9090: Prometheus web UI
az vm open-port --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --port 9090 --priority 120 --output none
# Port 8000: ClamAV upload gateway
az vm open-port --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --port 8000 --priority 130 --output none

echo "[PHASE 4] NSG ports 8080, 3000, 9090, 8000 opened."

# ---- PHASE 5: CLONE & DEPLOY ----
echo ""
echo "[PHASE 5] Cloning repository and running vm-setup.sh on Azure VM..."
echo "Waiting 30 seconds for VM SSH to become fully active..."
sleep 30

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$ADMIN_USER@$PUBLIC_IP" << REMOTE_DEPLOY
set -e

echo "[REMOTE] Cloning repository..."
git clone $REPO_URL ~/ebpf-firewall || (cd ~/ebpf-firewall && git pull)

echo "[REMOTE] Running automated setup (packages, build, systemd, observability)..."
cd ~/ebpf-firewall
sudo bash scripts/vm-setup.sh

echo "[REMOTE] Deployment complete."
REMOTE_DEPLOY

echo "[PHASE 5] Full stack deployed via vm-setup.sh."

# ---- DEPLOYMENT COMPLETE ----
echo ""
echo "=============================================="
echo " DEPLOYMENT COMPLETE"
echo "=============================================="
echo ""
echo " Azure VM Public IP:  $PUBLIC_IP"
echo ""
echo " Access Points:"
echo "   Grafana Dashboard:  http://$PUBLIC_IP:3000"
echo "   Prometheus:         http://$PUBLIC_IP:9090"
echo "   Raw Metrics:        http://$PUBLIC_IP:8080/metrics"
echo "   Upload Gateway:     http://$PUBLIC_IP:8000/upload"
echo "   Health Check:       http://$PUBLIC_IP:8080/healthz"
echo ""
echo " SSH Access:"
echo "   ssh -o StrictHostKeyChecking=no $ADMIN_USER@$PUBLIC_IP"
echo ""
echo " Firewall Logs:"
echo "   ssh -o StrictHostKeyChecking=no $ADMIN_USER@$PUBLIC_IP 'sudo journalctl -u ebpf-shield -f'"
echo ""
echo "=============================================="
