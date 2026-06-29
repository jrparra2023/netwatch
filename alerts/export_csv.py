"""
NetWatch — export_csv.py
Exporta alertas de alerts.json a CSV para análisis.
Autor: José Rafael Parra Dugarte
"""

import json
import os
import csv
from datetime import datetime, timezone

ALERT_PATH  = os.path.join(os.path.dirname(__file__), "../logs/alerts.json")
EXPORT_PATH = os.path.join(os.path.dirname(__file__), "../logs/alerts_export.csv")


def load_alerts():
    alerts = []
    if not os.path.exists(ALERT_PATH):
        print(f"[ERROR] No se encontró {ALERT_PATH}")
        return alerts
    with open(ALERT_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts


def export_to_csv(alerts):
    if not alerts:
        print("[INFO] No hay alertas para exportar.")
        return

    # Campos estándar para el CSV
    fieldnames = [
        "detected_at", "type", "severity",
        "src_ip", "dst_ip", "message", "count", "score"
    ]

    os.makedirs(os.path.dirname(EXPORT_PATH), exist_ok=True)
    with open(EXPORT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for alert in alerts:
            # Normaliza campos opcionales
            row = {
                "detected_at": alert.get("detected_at", ""),
                "type":        alert.get("type", ""),
                "severity":    alert.get("severity", ""),
                "src_ip":      alert.get("src_ip", ""),
                "dst_ip":      alert.get("dst_ip", ""),
                "message":     alert.get("message", ""),
                "count":       alert.get("count", alert.get("dns_queries", "")),
                "score":       "",
            }
            writer.writerow(row)

    print(f"[INFO] {len(alerts)} alerta(s) exportadas a {EXPORT_PATH}")


if __name__ == "__main__":
    print("[NetWatch] Exportando alertas a CSV...\n")
    alerts = load_alerts()
    print(f"[INFO] {len(alerts)} alerta(s) encontradas.")
    export_to_csv(alerts)
