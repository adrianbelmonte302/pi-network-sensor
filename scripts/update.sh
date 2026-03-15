#!/usr/bin/env bash
set -e

APP_DIR="/opt/pi-network-sensor"
SERVICE_NAME="pi-network-sensor.service"

cd "$APP_DIR"

echo "[*] Haciendo git pull..."
git pull

echo "[*] Actualizando entorno Python..."
source .venv/bin/activate
pip install -r requirements.txt

echo "[*] Reiniciando servicio..."
sudo systemctl restart $SERVICE_NAME

echo "[*] Estado:"
sudo systemctl status $SERVICE_NAME --no-pager