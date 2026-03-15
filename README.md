# Pi Network Sensor

Sensor ligero para Raspberry Pi con interfaz web para inventario de dispositivos LAN y Bluetooth.

## Funciones

- Descubrimiento LAN con `arp-scan`
- Descubrimiento Bluetooth con `bluetoothctl`
- Inventario persistente en SQLite
- Alias, notas, tipo y aprobado/no aprobado
- Historial de observaciones (primera y última vez visto)
- Eliminación de dispositivos conocidos
- Filtros:
  - Todo
  - Solo desconocidos
  - Solo nuevos
  - Solo no aprobados
- Búsqueda en pantalla por MAC/IP/vendor/alias
- Botón para forzar escaneo (LAN + Bluetooth) desde la interfaz web

## Instalación en Raspberry Pi

Clonar en la Raspberry:

```bash
cd /opt
git clone https://github.com/adrianbelmonte302/pi-network-sensor.git /opt/pi-network-sensor
cd /opt/pi-network-sensor
chmod +x scripts/install.sh scripts/update.sh
bash scripts/install.sh