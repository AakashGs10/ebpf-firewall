#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:/snap/bin:/usr/local/go/bin"

echo "== packages =="
sudo apt-get update -y
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y \
  clang llvm gcc make libbpf-dev "linux-headers-$(uname -r)" docker.io docker-compose-v2 clamav-daemon curl openssl
command -v go >/dev/null || sudo snap install go --classic
sudo systemctl enable --now docker

echo "== clamav =="
sudo systemctl stop clamav-freshclam || true
sudo freshclam || echo "freshclam warning (database may already be current)"
sudo systemctl enable --now clamav-freshclam
sudo systemctl restart clamav-daemon
for i in $(seq 1 60); do [ -S /var/run/clamav/clamd.ctl ] && break; sleep 3; done
[ -S /var/run/clamav/clamd.ctl ] || { echo "FAIL: clamd socket missing"; exit 1; }

echo "== secrets (created once, never committed) =="
if [ ! -f /etc/ebpf-shield.env ]; then
  TOKEN="$(openssl rand -hex 16)"
  printf 'IFACE=eth0\nUPLOAD_TOKEN=%s\nBAN_ON_INFECTED=0\n' "$TOKEN" | sudo tee /etc/ebpf-shield.env >/dev/null
  sudo chmod 600 /etc/ebpf-shield.env
fi
if [ ! -f .env ]; then
  echo "GRAFANA_PASSWORD=$(openssl rand -hex 12)" > .env
  chmod 600 .env
fi

echo "== build =="
clang -O2 -g -Wall -target bpf -I/usr/include/$(uname -m)-linux-gnu -c kernel/xdp_telemetry.c -o kernel/xdp_telemetry.o
go build -o shield .

echo "== systemd service =="
sudo tee /etc/systemd/system/ebpf-shield.service >/dev/null <<EOF
[Unit]
Description=eBPF XDP firewall and virus-scanning upload gateway
After=network-online.target clamav-daemon.service
Wants=network-online.target

[Service]
WorkingDirectory=$PWD
EnvironmentFile=/etc/ebpf-shield.env
ExecStartPre=-/usr/sbin/ip link set dev eth0 xdp off
ExecStart=$PWD/shield
ExecStopPost=-/usr/sbin/ip link set dev eth0 xdp off
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable ebpf-shield
sudo systemctl restart ebpf-shield

echo "== prometheus + grafana =="
sudo docker compose down --remove-orphans || true
sudo docker compose up -d
sleep 10
PW="$(grep '^GRAFANA_PASSWORD=' .env | cut -d= -f2)"
sudo docker compose exec -T grafana grafana cli admin reset-admin-password "$PW" || true

sleep 5
echo "== status =="
systemctl is-active ebpf-shield clamav-daemon docker
sudo journalctl -u ebpf-shield -n 15 --no-pager
