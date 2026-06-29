"""
NetWatch — suricata_integration.py
Compara alertas de NetWatch vs alertas de Suricata (IDS ground truth).
Autor: José Rafael Parra Dugarte
"""

import json
import os
from datetime import datetime, timezone

SURICATA_LOG = "/var/log/suricata/eve.json"
NETWATCH_ALERTS = os.path.join(os.path.dirname(__file__), "../logs/alerts.json")
COMPARISON_PATH = os.path.join(os.path.dirname(__file__), "../logs/suricata_comparison.json")


def load_suricata_alerts():
    """Carga alertas de Suricata desde eve.json."""
    alerts = []
    if not os.path.exists(SURICATA_LOG):
        print(f"[WARN] Suricata log no encontrado en {SURICATA_LOG}")
        print("[INFO] Asegúrate de que Suricata esté corriendo: sudo suricata -i eth0 -D")
        return alerts

    with open(SURICATA_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append({
                        "timestamp":   event.get("timestamp", ""),
                        "src_ip":      event.get("src_ip", ""),
                        "dst_ip":      event.get("dest_ip", ""),
                        "proto":       event.get("proto", ""),
                        "signature":   event.get("alert", {}).get("signature", ""),
                        "category":    event.get("alert", {}).get("category", ""),
                        "severity":    event.get("alert", {}).get("severity", ""),
                    })
            except json.JSONDecodeError:
                continue
    return alerts


def load_netwatch_alerts():
    """Carga alertas generadas por NetWatch."""
    alerts = []
    if not os.path.exists(NETWATCH_ALERTS):
        print(f"[WARN] No se encontraron alertas de NetWatch en {NETWATCH_ALERTS}")
        return alerts
    with open(NETWATCH_ALERTS, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts


def compare_alerts(netwatch_alerts, suricata_alerts):
    """
    Compara IPs detectadas por NetWatch vs Suricata.
    Identifica: matches, solo NetWatch, solo Suricata.
    """
    nw_ips = set(a.get("src_ip") for a in netwatch_alerts)
    su_ips = set(a.get("src_ip") for a in suricata_alerts)

    matches      = nw_ips & su_ips   # detectadas por ambos
    only_netwatch = nw_ips - su_ips  # NetWatch detectó, Suricata no
    only_suricata = su_ips - nw_ips  # Suricata detectó, NetWatch no

    return {
        "matches":       sorted(matches),
        "only_netwatch": sorted(only_netwatch),
        "only_suricata": sorted(only_suricata),
    }


def generate_comparison_report(netwatch_alerts, suricata_alerts, comparison):
    """Genera reporte de comparación."""
    total_nw = len(netwatch_alerts)
    total_su = len(suricata_alerts)
    matched  = len(comparison["matches"])

    # Precision: de lo que NetWatch alertó, cuánto coincide con Suricata
    precision = (matched / total_nw * 100) if total_nw > 0 else 0

    report = {
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "netwatch_alerts":      total_nw,
        "suricata_alerts":      total_su,
        "matched_ips":          matched,
        "precision_pct":        round(precision, 2),
        "only_netwatch_ips":    comparison["only_netwatch"],
        "only_suricata_ips":    comparison["only_suricata"],
        "matched_ip_list":      comparison["matches"],
    }

    print(f"\n{'='*50}")
    print(f"  NetWatch vs Suricata — Comparison Report")
    print(f"{'='*50}")
    print(f"  NetWatch alerts : {total_nw}")
    print(f"  Suricata alerts : {total_su}")
    print(f"  Matched IPs     : {matched}")
    print(f"  Precision       : {precision:.1f}%")
    print(f"\n  Only NetWatch   : {comparison['only_netwatch'] or 'none'}")
    print(f"  Only Suricata   : {comparison['only_suricata'] or 'none'}")
    print(f"  Both detected   : {comparison['matches'] or 'none'}")
    print(f"{'='*50}\n")

    return report


def save_report(report):
    os.makedirs(os.path.dirname(COMPARISON_PATH), exist_ok=True)
    with open(COMPARISON_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[INFO] Reporte guardado en {COMPARISON_PATH}")


if __name__ == "__main__":
    print("[NetWatch] Iniciando comparación con Suricata...\n")

    netwatch_alerts = load_netwatch_alerts()
    suricata_alerts = load_suricata_alerts()

    print(f"[INFO] NetWatch: {len(netwatch_alerts)} alerta(s)")
    print(f"[INFO] Suricata: {len(suricata_alerts)} alerta(s)")

    comparison = compare_alerts(netwatch_alerts, suricata_alerts)
    report     = generate_comparison_report(netwatch_alerts, suricata_alerts, comparison)
    save_report(report)
