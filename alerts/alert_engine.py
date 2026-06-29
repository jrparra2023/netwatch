"""
NetWatch — alert_engine.py
Motor central de alertas. Consolida alertas de todos los módulos,
aplica scoring de severidad y genera reporte de resumen.
Autor: José Rafael Parra Dugarte
"""

from datetime import datetime, timezone
import json
import os
import sys

# Agrega el directorio raíz al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.port_scanner import load_packets, detect_port_scans
from analysis.dns_analyzer import analyze_dns

ALERT_PATH   = os.path.join(os.path.dirname(__file__), "../logs/alerts.json")
REPORT_PATH  = os.path.join(os.path.dirname(__file__), "../logs/report.json")

# Scoring por severidad
SEVERITY_SCORE = {
    "HIGH":   10,
    "MEDIUM":  5,
    "LOW":     1,
}


def load_existing_alerts():
    """Carga alertas previas del archivo de log."""
    alerts = []
    if not os.path.exists(ALERT_PATH):
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


def score_alerts(alerts):
    """Calcula score total y agrupa por IP."""
    ip_scores = {}
    for alert in alerts:
        src_ip   = alert.get("src_ip", "unknown")
        severity = alert.get("severity", "LOW")
        score    = SEVERITY_SCORE.get(severity, 1)

        if src_ip not in ip_scores:
            ip_scores[src_ip] = {
                "ip":      src_ip,
                "score":   0,
                "alerts":  [],
                "HIGH":    0,
                "MEDIUM":  0,
                "LOW":     0,
            }

        ip_scores[src_ip]["score"]    += score
        ip_scores[src_ip]["alerts"].append(alert)
        ip_scores[src_ip][severity]   += 1

    return ip_scores


def classify_threat(score):
    """Clasifica el nivel de amenaza por score acumulado."""
    if score >= 20:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"


def generate_report(ip_scores):
    """Genera reporte JSON de resumen."""
    report = {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "total_ips":     len(ip_scores),
        "total_alerts":  sum(len(v["alerts"]) for v in ip_scores.values()),
        "threat_summary": [],
    }

    # Ordena IPs por score descendente
    sorted_ips = sorted(ip_scores.values(), key=lambda x: x["score"], reverse=True)

    for entry in sorted_ips:
        threat_level = classify_threat(entry["score"])
        summary = {
            "ip":           entry["ip"],
            "threat_level": threat_level,
            "score":        entry["score"],
            "HIGH":         entry["HIGH"],
            "MEDIUM":       entry["MEDIUM"],
            "LOW":          entry["LOW"],
            "total_alerts": len(entry["alerts"]),
        }
        report["threat_summary"].append(summary)

        # Imprime en consola
        print(
            f"[{threat_level:8}] IP: {entry['ip']:18} "
            f"Score: {entry['score']:3} | "
            f"HIGH: {entry['HIGH']} MEDIUM: {entry['MEDIUM']} LOW: {entry['LOW']}"
        )

    return report


def save_report(report):
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[INFO] Reporte guardado en {REPORT_PATH}")


def run_all_detectors():
    """Corre todos los detectores y consolida alertas."""
    print("[NetWatch] Ejecutando todos los detectores...\n")

    packets = load_packets()
    print(f"[INFO] {len(packets)} paquetes cargados.\n")

    # Limpia alertas anteriores para reporte fresco
    if os.path.exists(ALERT_PATH):
        os.remove(ALERT_PATH)

    # Corre detectores
    print("── Port Scan Detector ──")
    port_alerts = detect_port_scans(packets)

    print("\n── DNS Anomaly Detector ──")
    dns_alerts = analyze_dns(packets)

    # Guarda todas las alertas
    all_alerts = port_alerts + dns_alerts
    os.makedirs(os.path.dirname(ALERT_PATH), exist_ok=True)
    with open(ALERT_PATH, "w") as f:
        for alert in all_alerts:
            f.write(json.dumps(alert) + "\n")

    return all_alerts


if __name__ == "__main__":
    # 1. Corre todos los detectores
    all_alerts = run_all_detectors()

    # 2. Scoring y reporte
    print(f"\n[INFO] {len(all_alerts)} alerta(s) totales generadas.\n")
    print("── Threat Summary ──")

    ip_scores = score_alerts(all_alerts)
    report    = generate_report(ip_scores)

    # 3. Guarda reporte
    save_report(report)
