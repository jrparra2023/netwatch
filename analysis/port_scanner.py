"""
NetWatch — port_scanner.py
Detecta escaneos de puertos analizando el log de captura.
Un escaneo = una IP tocando 10+ puertos distintos en menos de 30 segundos.
Autor: José Rafael Parra Dugarte
"""

from datetime import datetime, timezone
import json
import os
from collections import defaultdict

LOG_PATH = os.path.join(os.path.dirname(__file__), "../logs/capture.json")
ALERT_PATH = os.path.join(os.path.dirname(__file__), "../logs/alerts.json")

# Umbrales configurables
PORT_THRESHOLD = 10   # puertos distintos
TIME_WINDOW    = 30   # segundos


def load_packets():
    """Carga todos los paquetes del log de captura."""
    packets = []
    if not os.path.exists(LOG_PATH):
        print(f"[ERROR] No se encontró {LOG_PATH} — ejecuta sniffer.py primero.")
        return packets
    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    packets.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return packets


def detect_port_scans(packets):
    """
    Agrupa paquetes por IP origen y detecta si tocó
    PORT_THRESHOLD puertos distintos en TIME_WINDOW segundos.
    """
    # ip_src -> lista de (timestamp, dst_port)
    activity = defaultdict(list)

    for pkt in packets:
        if pkt.get("dst_port") and pkt.get("src_ip"):
            try:
                ts = datetime.fromisoformat(pkt["timestamp"]).replace(tzinfo=timezone.utc)
                activity[pkt["src_ip"]].append((ts, pkt["dst_port"]))
            except Exception:
                continue

    alerts = []
    for src_ip, events in activity.items():
        events.sort(key=lambda x: x[0])  # orden cronológico

        # Ventana deslizante
        for i in range(len(events)):
            window = [
                e for e in events[i:]
                if (e[0] - events[i][0]).total_seconds() <= TIME_WINDOW
            ]
            ports_hit = set(e[1] for e in window)

            if len(ports_hit) >= PORT_THRESHOLD:
                alert = {
                    "type":      "PORT_SCAN",
                    "severity":  "HIGH",
                    "src_ip":    src_ip,
                    "ports_hit": sorted(ports_hit),
                    "count":     len(ports_hit),
                    "window_start": events[i][0].isoformat(),
                    "detected_at":  datetime.now(timezone.utc).isoformat(),
                    "message": (
                        f"Posible escaneo de puertos desde {src_ip}: "
                        f"{len(ports_hit)} puertos en {TIME_WINDOW}s"
                    )
                }
                alerts.append(alert)
                print(f"[ALERTA HIGH] {alert['message']}")
                break  # una alerta por IP es suficiente

    return alerts


def save_alerts(alerts):
    """Guarda alertas en alerts.json (append)."""
    if not alerts:
        print("[INFO] No se detectaron escaneos de puertos.")
        return
    os.makedirs(os.path.dirname(ALERT_PATH), exist_ok=True)
    with open(ALERT_PATH, "a") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"[INFO] {len(alerts)} alerta(s) guardadas en {ALERT_PATH}")


if __name__ == "__main__":
    print("[NetWatch] Analizando captura en busca de escaneos de puertos...\n")
    packets = load_packets()
    print(f"[INFO] {len(packets)} paquetes cargados.")
    alerts  = detect_port_scans(packets)
    save_alerts(alerts)
