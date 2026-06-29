# NetWatch — Network Traffic Analyzer & Threat Detector

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.7-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Open-source network traffic analyzer with real-time threat detection. Built on Kali Linux using Python and Scapy, NetWatch captures live packets, detects port scans, and identifies DNS anomalies generating severity-based alerts logged for incident response workflows.

## Features

- Real-time packet capture — TCP, UDP, ICMP via Scapy
- Port scan detection — flags IPs touching 10+ ports within 30 seconds (HIGH)
- DNS anomaly detection — excessive queries and high-risk TLDs (MEDIUM/HIGH)
- Structured alert logging — JSON with timestamp, source IP, severity, reason

## Tech Stack

Python 3 · Scapy · Flask · Pandas · tshark · nmap · pytest

## Quick Start

git clone https://github.com/jrparra2023/netwatch.git
cd netwatch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Usage

sudo venv/bin/python3 capture/sniffer.py
python3 analysis/port_scanner.py
python3 analysis/dns_analyzer.py

## Detection Examples

PORT SCAN (HIGH): IP contacts 10+ distinct ports in 30 seconds
[ALERTA HIGH] Posible escaneo de puertos desde 10.0.2.15: 14 puertos en 30s

DNS ANOMALY (MEDIUM): Single IP exceeds 50 DNS queries
[ALERTA MEDIUM] Volumen DNS inusual desde 10.0.2.15: 60 consultas

## Roadmap

- [x] Live packet capture
- [x] Port scan detection
- [x] DNS anomaly analysis
- [ ] Alert engine
- [ ] Flask dashboard
- [ ] Unit tests

## Author

Jose Rafael Parra Dugarte
Electronics and Telecommunications Engineering — Universidad del Cauca
GRIAL Wireless Networks Research Group
