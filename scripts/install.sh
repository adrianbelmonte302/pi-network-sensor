#!/usr/bin/env bash
set -e

APP_DIR="/opt/pi-network-sensor"
SERVICE_NAME="pi-network-sensor.service"

echo "[*] Instalando dependencias del sistema..."
sudo apt update
sudo apt install -y python3-venv python3-pip arp-scan nmap iw wireless-tools bluez bluetooth git

echo "[*] Creando entorno virtual..."
cd "$APP_DIR"
python3 -m venv .venv
source .venv/bin/activate

echo "[*] Instalando dependencias Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Ajustando capacidades..."
sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan || true
NMAP_BIN="$(command -v nmap || true)"
if [ -n "$NMAP_BIN" ]; then
  sudo setcap cap_net_raw,cap_net_admin+eip "$NMAP_BIN" || true
fi

echo "[*] Instalando servicio systemd..."
sudo cp systemd/$SERVICE_NAME /etc/systemd/system/$SERVICE_NAME
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

echo "[*] Activando Bluetooth..."
sudo systemctl enable bluetooth
sudo systemctl restart bluetooth || true

echo "[*] Instalación completada."
echo "Abre: http://$(hostname -I | awk '{print $1}'):8088/ui"
