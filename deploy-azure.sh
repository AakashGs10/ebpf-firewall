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
az login --use-device-code
echo "[PHASE 1] Authentication successful."

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
PUBLIC_IP=$(echo "$VM_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['publicIpAddress'])")
echo "[PHASE 3] VM provisioned. Public IP: $PUBLIC_IP"

# ---- PHASE 4: OPEN NETWORK SECURITY GROUP PORTS ----
echo ""
echo "[PHASE 4] Configuring Azure NSG firewall rules..."

# Port 8080: Go metrics exporter (Prometheus scrape target)
az vm open-port \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --port 8080 \
  --priority 100 \
  --output table

# Port 3000: Grafana dashboard (web UI)
az vm open-port \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --port 3000 \
  --priority 110 \
  --output table

# Port 9090: Prometheus web UI (optional, for debugging)
az vm open-port \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --port 9090 \
  --priority 120 \
  --output table

echo "[PHASE 4] NSG ports 8080, 3000, 9090 opened."

# ---- PHASE 5: BOOTSTRAP THE CLOUD NODE ----
echo ""
echo "[PHASE 5] Bootstrapping kernel dependencies on Azure VM..."

ssh -o StrictHostKeyChecking=no "$ADMIN_USER@$PUBLIC_IP" << 'REMOTE_SCRIPT'
set -e

echo "[REMOTE] Updating package index..."
sudo apt-get update -y

echo "[REMOTE] Installing eBPF toolchain (clang, llvm, libbpf)..."
sudo apt-get install -y clang llvm gcc make libbpf-dev linux-headers-$(uname -r)

echo "[REMOTE] Installing Go..."
sudo snap install go --classic

echo "[REMOTE] Installing Docker..."
sudo apt-get install -y docker.io docker-compose-v2
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

echo "[REMOTE] Bootstrap complete."
REMOTE_SCRIPT

echo "[PHASE 5] Cloud node bootstrapped."

# ---- PHASE 6: DEPLOY THE CODEBASE ----
echo ""
echo "[PHASE 6] Cloning eBPF project to Azure VM..."

ssh "$ADMIN_USER@$PUBLIC_IP" << REMOTE_DEPLOY
set -e

echo "[REMOTE] Cloning repository..."
git clone $REPO_URL ~/ebpf-firewall || (cd ~/ebpf-firewall && git pull)

echo "[REMOTE] Compiling eBPF kernel program natively..."
cd ~/ebpf-firewall
clang -O2 -g -Wall -target bpf -c kernel/xdp_telemetry.c -o kernel/xdp_telemetry.o

echo "[REMOTE] Downloading Go dependencies..."
go mod tidy

echo "[REMOTE] Code deployment complete."
REMOTE_DEPLOY

echo "[PHASE 6] Codebase deployed and compiled on cloud node."

# ---- PHASE 7: LAUNCH TELEMETRY STACK ----
echo ""
echo "[PHASE 7] Starting Prometheus + Grafana via Docker Compose..."

ssh "$ADMIN_USER@$PUBLIC_IP" << 'REMOTE_TELEMETRY'
set -e

cd ~/ebpf-firewall
sudo docker compose up -d

echo "[REMOTE] Telemetry stack active."
REMOTE_TELEMETRY

echo "[PHASE 7] Prometheus + Grafana running on cloud node."

# ---- PHASE 8: ACTIVATE THE SHIELD ----
echo ""
echo "[PHASE 8] Deploying eBPF shield on Azure network interface..."

ssh "$ADMIN_USER@$PUBLIC_IP" << 'REMOTE_SHIELD'
set -e

cd ~/ebpf-firewall
sudo nohup go run main.go > /var/log/ebpf-firewall.log 2>&1 &

echo "[REMOTE] eBPF Firewall deployed and logging to /var/log/ebpf-firewall.log"
REMOTE_SHIELD

echo "[PHASE 8] Shield active on cloud node."

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
echo ""
echo " SSH Access:"
echo "   ssh $ADMIN_USER@$PUBLIC_IP"
echo ""
echo " Firewall Logs:"
echo "   ssh $ADMIN_USER@$PUBLIC_IP 'tail -f /var/log/ebpf-firewall.log'"
echo ""
echo "=============================================="
