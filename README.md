# Pi Network Sensor

Sensor ligero para Raspberry Pi con interfaz web para inventario de dispositivos LAN y Bluetooth.

## Funciones

- Descubrimiento LAN con `arp-scan`
- Descubrimiento Bluetooth con `bluetoothctl`
- Inventario persistente en SQLite
- Alias, notas, tipo y aprobado/no aprobado
- Historial de observaciones (primera y ultima vez visto)
- Eliminacion de dispositivos conocidos
- Filtros:
  - Todo
  - Solo desconocidos
  - Solo nuevos
  - Solo no aprobados
- Busqueda en pantalla por MAC/IP/vendor/alias
- Boton para forzar escaneo (LAN + Bluetooth) desde la interfaz web
- Botones independientes para ejecutar escaneos LAN y Bluetooth con indicadores visuales
- Los dispositivos guardados y sus notas se cargan desde la base de datos incluso sin escanear y permanecen visibles aunque el escaneo falle.

## Estado actual (2026-03-29)

- App principal en `app.py` con FastAPI + Jinja2.
- Base de datos SQLite en `known.db`, inicializada por `helpers/db.py` al arrancar.
- Interfaz web en `templates/ui.html` y `templates/device_detail.html`.
- Escaneo LAN con `arp-scan` (requiere permisos de red).
- Escaneo Bluetooth con `bluetoothctl` (requiere adaptador activo y permisos).
- Escaneo WiFi con `iw` + `iwlist` (requiere `wireless-tools` y permisos).
- Escaneos periódicos en background con caché en memoria.
- Monitor de presencia con historial en DB y `logs/monitor_history.log`.

## Dependencias del sistema

- `arp-scan` (LAN)
- `nmap` (port scan)
- `iw`, `iwlist` (WiFi)
- `bluez`, `bluetoothctl` (Bluetooth)
- `python3-venv`, `python3-pip`
- `sqlite3` (diagnóstico / soporte)

## Variables de entorno

- `ARP_SCAN`: ruta a `arp-scan` si no esta en PATH.
- `BLUETOOTHCTL`: ruta a `bluetoothctl` si no esta en PATH.
- `BLE_SCAN_DURATION`: segundos de escaneo BLE (default 8).
- `SCAN_INTERVAL_SECONDS`: intervalo del escaneo periodico (default 300).
- `ABSENCE_SCAN_THRESHOLD`: numero de escaneos sin ver dispositivo para marcarlo ausente (default 3).
- `MONITOR_DEFAULT_INTERVAL_MINUTES`: intervalo del monitor (default 3).
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`: notificaciones Telegram.

## Endpoints utiles

- `GET /ui`: interfaz principal.
- `GET /api/monitor`: estado de presencia y historial.
- `POST /lan/scan`: escaneo de puertos bajo demanda.
- `GET /api/scan-status`: estado de escaneo bajo demanda.
- `GET /device/{identifier}`: detalle de dispositivo LAN.

## Datos y tablas

- `known_devices`: alias, categoria, notas, aprobado.
- `observations`: primera/ultima vez, IP, vendor, display_name.
- `events`: eventos y alertas.
- `port_scans`: puertos y servicios abiertos.
- `scan_history`: historial de escaneos de puertos.
- `wifi_observations`: BSSID/SSID y canales.
- `monitor_history`, `monitor_status`: presencia y cambios.

## Registro y logs

- Log local del monitor: `logs/monitor_history.log`
- Eventos en DB: tabla `events`

## Problemas conocidos (por revisar)

- nmap con perfiles medio/profundidad puede requerir permisos elevados en algunos sistemas. Si falla, verificar capacidades y permisos.
- Bluetooth y WiFi suelen requerir permisos de grupo (bluetooth, netdev) o root en Raspberry Pi.
- Acceso a /var/log/auth.log, /var/log/syslog o /var/log/messages puede fallar sin permisos; en ese caso no se veran eventos del sistema.
- Si /opt/pi-network-sensor no es escribible por el usuario del servicio, fallan DB y logs.
- Posible mojibake en textos (tildes) por encoding inconsistente. Revisar y forzar UTF-8.

## Troubleshooting rapido

- LAN no funciona: verificar `arp-scan` y permisos (`setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan`).
- Port scan falla: verificar `nmap` y permisos, o cambiar a un perfil que no requiera raw sockets.
- BLE no detecta: `systemctl status bluetooth` y permisos del usuario.
- WiFi no detecta: validar interfaz con `iw dev`.
- DB no guarda: revisar permisos de escritura en `/opt/pi-network-sensor`.

## Health check rapido

- Ver servicio: `sudo systemctl status pi-network-sensor.service --no-pager`
- Ver logs: `sudo journalctl -u pi-network-sensor.service -n 100 --no-pager`
- Probar UI: `http://<ip-raspberry>:8088/ui`
- Probar API monitor: `http://<ip-raspberry>:8088/api/monitor`

## Notas de encoding

- Mantener los archivos en UTF-8 sin BOM para evitar mojibake en la interfaz y README.
- Si se edita desde Windows, forzar UTF-8 en el editor antes de guardar.

## Instalacion en Raspberry Pi

Clonar en la Raspberry:

```bash
cd /opt
git clone https://github.com/adrianbelmonte302/pi-network-sensor.git /opt/pi-network-sensor
cd /opt/pi-network-sensor
chmod +x scripts/install.sh scripts/update.sh
bash scripts/install.sh
```

El servicio systemd (`systemd/pi-network-sensor.service`) arranca `uvicorn` dentro del entorno virtual y esta configurado para ejecutarse como el usuario `adrian`; cambialo si necesitas otro usuario en tu Raspberry Pi.

















