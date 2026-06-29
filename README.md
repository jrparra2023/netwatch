# NetWatch — Network Traffic Analyzer & Threat Detector

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.7-green)
![Tests](https://img.shields.io/badge/Tests-15%2F15%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Open-source network traffic analyzer with real-time threat detection. Built on Kali Linux using Python and Scapy, NetWatch captures live packets, detects port scans, identifies DNS anomalies, and consolidates severity-scored alerts into a real-time Flask dashboard — designed for incident response workflows.

---

## Features

- Real-time packet capture — TCP, UDP, ICMP via Scapy
- Port scan detection — flags IPs touching 10+ ports within 30 seconds (HIGH)
- DNS anomaly detection — excessive queries and high-risk TLDs (MEDIUM/HIGH)
- Unified alert engine — consolidates multi-source alerts with cumulative severity scoring
- Real-time Flask dashboard — threat summary, alert log, auto-refresh every 10s
- Structured alert logging — JSON with timestamp, source IP, severity, and reason
- 15 unit tests — pytest coverage for all detection modules (15/15 passing)

---

## Architecture
---

## Tech Stack

| Tool | Role |
|------|------|
| Python 3.13 | Core language |
| Scapy 2.7 | Packet capture and parsing |
| Flask | Real-time web dashboard |
| Pandas | Log processing |
| tshark | Traffic validation |
| nmap | Test traffic generation |
| pytest | Unit testing (15/15 passing) |

---

## Quick Start

### Requirements
- Kali Linux (or any Debian-based distro)
- Python 3.x
- Root privileges for packet capture

### Installation

```bash
git clone https://github.com/jrparra2023/netwatch.git
cd netwatch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

**1. Capture live traffic:**
```bash
sudo venv/bin/python3 capture/sniffer.py
```

**2. Detect port scans:**
```bash
python3 analysis/port_scanner.py
```

**3. Analyze DNS traffic:**
```bash
python3 analysis/dns_analyzer.py
```

**4. Run unified alert engine:**
```bash
python3 alerts/alert_engine.py
```

**5. Launch dashboard:**
```bash
python3 dashboard/app.py
# Open http://localhost:5000
```

**6. Run tests:**
```bash
pytest tests/test_detector.py -v
```

---

## Detection Examples

### Port Scan — HIGH
Triggered when a single IP contacts 10+ distinct ports within a 30-second window.

### DNS Anomaly — MEDIUM
Triggered when DNS query volume from a single IP exceeds 50 requests.

### Threat Summary — Alert Engine
Cumulative scoring: HIGH=10pts, MEDIUM=5pts, LOW=1pt. CRITICAL threshold at 20pts.

---

## Test Results
| Test Class | Tests | Status |
|---|---|---|
| TestPortScanner | 5 | PASSED |
| TestDnsAnalyzer | 4 | PASSED |
| TestCheckSuspicious | 6 | PASSED |

---

## Roadmap

- [x] Live packet capture (sniffer.py)
- [x] Port scan detection (port_scanner.py)
- [x] DNS anomaly analysis (dns_analyzer.py)
- [x] Unified alert engine with severity scoring (alert_engine.py)
- [x] Real-time Flask dashboard (dashboard/app.py)
- [x] Unit tests — 15/15 passing (pytest)
- [ ] config/rules.yaml — configurable thresholds without code changes
- [ ] Suricata integration — compare NetWatch alerts vs IDS ground truth
- [ ] Export alerts to CSV for analysis

---

## Author

**Jose Rafael Parra Dugarte**
Electronics and Telecommunications Engineering — Universidad del Cauca
GRIAL Wireless Networks Research Group

[![LinkedIn](https://img.shields.io/badge/LinkedIn-josé--rafael--parra--dugarte-blue)](https://linkedin.com/in/josé-rafael-parra-dugarte)
[![GitHub](https://img.shields.io/badge/GitHub-jrparra2023-black)](https://github.com/jrparra2023)
