# Pi Network Sensor

Sensor ligero para Raspberry Pi con interfaz web para inventario de dispositivos LAN y Bluetooth.

## Funciones

- Descubrimiento LAN con `arp-scan`
- Descubrimiento Bluetooth con `bluetoothctl`
- Inventario persistente en SQLite
- Alias, notas, tipo y aprobado/no aprobado
- Filtros:
  - Todo
  - Solo desconocidos
  - Solo nuevos
  - Solo no aprobados
- Botones para forzar escaneo LAN / WiFi / BT

## Instalación en Raspberry Pi

Clonar en la Raspberry:

```bash
cd /opt
git clone https://github.com/adrianbelmonte302/pi-network-sensor.git /opt/pi-network-sensor
cd /opt/pi-network-sensor
chmod +x scripts/install.sh scripts/update.sh
bash scripts/install.sh