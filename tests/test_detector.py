"""
NetWatch — test_detector.py
Tests unitarios para port_scanner y dns_analyzer.
Autor: José Rafael Parra Dugarte
"""

import sys
import os
import json
import pytest

# Path al raíz del proyecto
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.port_scanner import detect_port_scans
from analysis.dns_analyzer import analyze_dns, check_suspicious


# ── Fixtures ──────────────────────────────────────────────────────────────

def make_tcp_packet(src_ip, dst_port, timestamp="2026-01-01T00:00:00"):
    return {
        "timestamp": timestamp,
        "src_ip":    src_ip,
        "dst_ip":    "10.0.0.1",
        "protocol":  "TCP",
        "src_port":  12345,
        "dst_port":  dst_port,
        "length":    60,
        "flags":     "S",
    }

def make_udp_packet(src_ip, dst_port=53, src_port=54321, timestamp="2026-01-01T00:00:00"):
    return {
        "timestamp": timestamp,
        "src_ip":    src_ip,
        "dst_ip":    "200.21.200.10",
        "protocol":  "UDP",
        "src_port":  src_port,
        "dst_port":  dst_port,
        "length":    69,
        "flags":     None,
    }


# ── Port Scanner Tests ─────────────────────────────────────────────────────

class TestPortScanner:

    def test_no_scan_below_threshold(self):
        """Menos de 10 puertos distintos no genera alerta."""
        packets = [make_tcp_packet("192.168.1.1", port) for port in range(1, 9)]
        alerts = detect_port_scans(packets)
        assert len(alerts) == 0

    def test_scan_detected_above_threshold(self):
        """10+ puertos distintos en 30s genera alerta HIGH."""
        packets = [make_tcp_packet("192.168.1.100", port) for port in range(1, 15)]
        alerts = detect_port_scans(packets)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "HIGH"
        assert alerts[0]["type"] == "PORT_SCAN"
        assert alerts[0]["src_ip"] == "192.168.1.100"

    def test_scan_counts_distinct_ports_only(self):
        """Paquetes repetidos al mismo puerto no cuentan como escaneo."""
        packets = [make_tcp_packet("10.0.0.5", 80) for _ in range(50)]
        alerts = detect_port_scans(packets)
        assert len(alerts) == 0

    def test_multiple_ips_independent(self):
        """Cada IP se evalúa independientemente."""
        packets  = [make_tcp_packet("1.1.1.1", port) for port in range(1, 15)]
        packets += [make_tcp_packet("2.2.2.2", port) for port in range(1, 5)]
        alerts = detect_port_scans(packets)
        ips = [a["src_ip"] for a in alerts]
        assert "1.1.1.1" in ips
        assert "2.2.2.2" not in ips

    def test_alert_contains_required_fields(self):
        """Alerta tiene todos los campos requeridos."""
        packets = [make_tcp_packet("172.16.0.1", port) for port in range(1, 20)]
        alerts = detect_port_scans(packets)
        assert len(alerts) > 0
        alert = alerts[0]
        for field in ["type", "severity", "src_ip", "ports_hit", "count", "detected_at", "message"]:
            assert field in alert, f"Campo faltante: {field}"


# ── DNS Analyzer Tests ─────────────────────────────────────────────────────

class TestDnsAnalyzer:

    def test_no_alert_below_dns_threshold(self):
        """Menos de 50 consultas DNS no genera alerta."""
        packets = [make_udp_packet("10.0.0.1") for _ in range(30)]
        alerts = analyze_dns(packets)
        assert len(alerts) == 0

    def test_dns_volume_alert_above_threshold(self):
        """Más de 50 consultas DNS genera alerta MEDIUM."""
        packets = [make_udp_packet("10.0.0.2") for _ in range(60)]
        alerts = analyze_dns(packets)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "MEDIUM"
        assert alerts[0]["type"] == "DNS_TUNNELING"

    def test_no_dns_packets_no_alerts(self):
        """Sin paquetes DNS no hay alertas."""
        packets = [make_tcp_packet("10.0.0.1", 80) for _ in range(100)]
        alerts = analyze_dns(packets)
        assert len(alerts) == 0

    def test_non_dns_udp_ignored(self):
        """UDP en puertos distintos de 53 no cuenta como DNS."""
        packets = [make_udp_packet("10.0.0.3", dst_port=1234) for _ in range(100)]
        alerts = analyze_dns(packets)
        assert len(alerts) == 0


# ── check_suspicious Tests ─────────────────────────────────────────────────

class TestCheckSuspicious:

    def test_blacklisted_domain(self):
        suspicious, reason = check_suspicious("malware.com")
        assert suspicious is True
        assert "lista negra" in reason

    def test_suspicious_keyword(self):
        suspicious, reason = check_suspicious("secure-login.example.com")
        assert suspicious is True

    def test_high_risk_tld(self):
        suspicious, reason = check_suspicious("something.tk")
        assert suspicious is True
        assert ".tk" in reason

    def test_clean_domain(self):
        suspicious, reason = check_suspicious("google.com")
        assert suspicious is False
        assert reason == ""

    def test_clean_domain_gov(self):
        suspicious, reason = check_suspicious("universidad.edu.co")
        assert suspicious is False

    def test_xyz_tld_flagged(self):
        suspicious, reason = check_suspicious("steal-credentials.xyz")
        assert suspicious is True


# ── Runner ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
