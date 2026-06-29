"""
NetWatch — dns_analyzer.py
Detecta consultas DNS a dominios sospechosos o en lista negra.
Autor: José Rafael Parra Dugarte
"""

from datetime import datetime, timezone
import json
import os

LOG_PATH   = os.path.join(os.path.dirname(__file__), "../logs/capture.json")
ALERT_PATH = os.path.join(os.path.dirname(__file__), "../logs/alerts.json")

# Lista negra de dominios sospechosos — configurable
BLACKLIST = {
    "malware.com", "phishing-site.net", "evil.ru",
    "fakebank.tk", "steal-credentials.xyz", "botnet.cc",
    "ransomware.top", "exploit-kit.pw"
}

# Palabras clave sospechosas en dominios
SUSPICIOUS_KEYWORDS = [
    "login-", "secure-", "verify-", "account-", "update-",
    "banking", "paypal", "netflix", "-support", "helpdesk"
]


def load_packets():
    packets = []
    if not os.path.exists(LOG_PATH):
        print(f"[ERROR] No se encontró {LOG_PATH}")
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


def extract_dns_queries(packets):
    """Extrae paquetes UDP puerto 53 — tráfico DNS."""
    dns_packets = []
    for pkt in packets:
        if pkt.get("protocol") == "UDP" and (
            pkt.get("dst_port") == 53 or pkt.get("src_port") == 53
        ):
            dns_packets.append(pkt)
    return dns_packets


def check_suspicious(domain):
    """Retorna (es_sospechoso, razón)."""
    domain = domain.lower().strip()
    if domain in BLACKLIST:
        return True, f"Dominio en lista negra: {domain}"
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain:
            return True, f"Keyword sospechosa '{keyword}' en dominio: {domain}"
    # TLDs de alto riesgo
    for tld in [".tk", ".pw", ".xyz", ".top", ".cc", ".ru"]:
        if domain.endswith(tld):
            return True, f"TLD de alto riesgo '{tld}': {domain}"
    return False, ""


def analyze_dns(packets):
    """Analiza tráfico DNS y genera alertas."""
    dns_packets = extract_dns_queries(packets)
    print(f"[INFO] {len(dns_packets)} paquetes DNS encontrados.")

    alerts = []
    seen_ips = {}  # ip -> conteo de consultas DNS

    for pkt in dns_packets:
        src_ip = pkt.get("src_ip", "unknown")

        # Conteo de consultas por IP (detección de DNS tunneling)
        if pkt.get("dst_port") == 53:
            seen_ips[src_ip] = seen_ips.get(src_ip, 0) + 1

    # Alerta por volumen excesivo de consultas DNS (posible tunneling)
    for ip, count in seen_ips.items():
        if count > 50:
            alert = {
                "type":        "DNS_TUNNELING",
                "severity":    "MEDIUM",
                "src_ip":      ip,
                "dns_queries": count,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "message":     f"Volumen DNS inusual desde {ip}: {count} consultas"
            }
            alerts.append(alert)
            print(f"[ALERTA MEDIUM] {alert['message']}")

    # Analiza IPs de destino DNS contra lista negra
    dns_servers = {}
    for pkt in dns_packets:
        if pkt.get("dst_port") == 53:
            dst = pkt.get("dst_ip", "")
            suspicious, reason = check_suspicious(dst)
            if suspicious and dst not in dns_servers:
                dns_servers[dst] = reason
                alert = {
                    "type":        "DNS_BLACKLIST",
                    "severity":    "HIGH",
                    "src_ip":      pkt.get("src_ip"),
                    "dst_ip":      dst,
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "message":     reason
                }
                alerts.append(alert)
                print(f"[ALERTA HIGH] {alert['message']}")

    if not alerts:
        print("[INFO] No se detectaron anomalías DNS.")

    return alerts


def save_alerts(alerts):
    if not alerts:
        return
    os.makedirs(os.path.dirname(ALERT_PATH), exist_ok=True)
    with open(ALERT_PATH, "a") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"[INFO] {len(alerts)} alerta(s) guardadas en {ALERT_PATH}")


if __name__ == "__main__":
    print("[NetWatch] Analizando tráfico DNS...\n")
    packets = load_packets()
    print(f"[INFO] {len(packets)} paquetes totales cargados.")
    alerts = analyze_dns(packets)
    save_alerts(alerts)
