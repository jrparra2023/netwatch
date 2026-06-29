"""
NetWatch — sniffer.py
Captura paquetes en la interfaz de red y extrae campos clave.
Autor: José Rafael Parra Dugarte
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import json
import os

LOG_PATH = os.path.join(os.path.dirname(__file__), "../logs/capture.json")


def parse_packet(packet):
    """Extrae campos relevantes de cada paquete capturado."""
    if not packet.haslayer(IP):
        return None

    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip":    packet[IP].src,
        "dst_ip":    packet[IP].dst,
        "protocol":  None,
        "src_port":  None,
        "dst_port":  None,
        "length":    len(packet),
        "flags":     None,
    }

    if packet.haslayer(TCP):
        record["protocol"] = "TCP"
        record["src_port"] = packet[TCP].sport
        record["dst_port"] = packet[TCP].dport
        record["flags"]    = str(packet[TCP].flags)

    elif packet.haslayer(UDP):
        record["protocol"] = "UDP"
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport

    elif packet.haslayer(ICMP):
        record["protocol"] = "ICMP"

    else:
        record["protocol"] = "OTHER"

    return record


def log_packet(record):
    """Guarda el paquete en capture.json (append, un JSON por línea)."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")


def process_packet(packet):
    record = parse_packet(packet)
    if record:
        print(
            f"[{record['timestamp']}] {record['protocol']:5} "
            f"{record['src_ip']}:{record['src_port']} → "
            f"{record['dst_ip']}:{record['dst_port']} "
            f"len={record['length']}"
        )
        log_packet(record)


def start_capture(interface=None, packet_count=0, bpf_filter="ip"):
    """
    Inicia la captura.
    interface: None = Scapy elige automáticamente
    packet_count: 0 = captura indefinida (Ctrl+C para detener)
    bpf_filter: filtro Berkeley Packet Filter
    """
    print(f"[NetWatch] Iniciando captura en interfaz: {interface or 'auto'}")
    print(f"[NetWatch] Filtro: {bpf_filter} | Ctrl+C para detener\n")

    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=process_packet,
        count=packet_count,
        store=False,       # no acumula en RAM
    )


if __name__ == "__main__":
    # Scapy necesita privilegios root para capturar
    import sys
    if os.geteuid() != 0:
        print("[ERROR] Ejecuta con sudo: sudo python3 sniffer.py")
        sys.exit(1)

    start_capture()
