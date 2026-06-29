"""
NetWatch — app.py
Dashboard web para visualizar alertas en tiempo real.
Autor: José Rafael Parra Dugarte
"""

from flask import Flask, render_template_string, jsonify
from datetime import datetime, timezone
import json
import os

app = Flask(__name__)

ALERT_PATH  = os.path.join(os.path.dirname(__file__), "../logs/alerts.json")
REPORT_PATH = os.path.join(os.path.dirname(__file__), "../logs/report.json")


def load_alerts():
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


def load_report():
    if not os.path.exists(REPORT_PATH):
        return {}
    with open(REPORT_PATH, "r") as f:
        return json.load(f)


TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="10">
    <title>NetWatch Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 24px; }
        h1 { color: #58a6ff; font-size: 1.6rem; margin-bottom: 4px; }
        .subtitle { color: #8b949e; font-size: 0.85rem; margin-bottom: 32px; }

        .stats { display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }
        .card {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 20px 28px; min-width: 160px;
        }
        .card .num { font-size: 2rem; font-weight: bold; }
        .card .label { font-size: 0.78rem; color: #8b949e; margin-top: 4px; }
        .HIGH   { color: #f85149; }
        .MEDIUM { color: #e3b341; }
        .LOW    { color: #3fb950; }
        .CRITICAL { color: #ff7b72; }

        h2 { color: #58a6ff; font-size: 1rem; margin-bottom: 12px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }

        table { width: 100%; border-collapse: collapse; margin-bottom: 32px; font-size: 0.82rem; }
        th { background: #161b22; color: #8b949e; padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; }
        td { padding: 10px 12px; border-bottom: 1px solid #21262d; }
        tr:hover td { background: #161b22; }

        .badge {
            display: inline-block; padding: 2px 10px; border-radius: 12px;
            font-size: 0.75rem; font-weight: bold;
        }
        .badge.HIGH     { background: #3d1f1f; color: #f85149; }
        .badge.MEDIUM   { background: #3d2f0f; color: #e3b341; }
        .badge.LOW      { background: #1a2e1a; color: #3fb950; }
        .badge.CRITICAL { background: #4a1010; color: #ff7b72; }

        .footer { color: #484f58; font-size: 0.75rem; margin-top: 16px; }
    </style>
</head>
<body>
    <h1>⚡ NetWatch Dashboard</h1>
    <p class="subtitle">Network Traffic Analyzer & Threat Detector — auto-refresh every 10s</p>

    <!-- Stats -->
    <div class="stats">
        <div class="card">
            <div class="num">{{ total_alerts }}</div>
            <div class="label">Total Alerts</div>
        </div>
        <div class="card">
            <div class="num HIGH">{{ high_count }}</div>
            <div class="label">HIGH Severity</div>
        </div>
        <div class="card">
            <div class="num MEDIUM">{{ medium_count }}</div>
            <div class="label">MEDIUM Severity</div>
        </div>
        <div class="card">
            <div class="num">{{ total_ips }}</div>
            <div class="label">IPs Monitored</div>
        </div>
    </div>

    <!-- Threat Summary -->
    {% if threat_summary %}
    <h2>Threat Summary by IP</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Threat Level</th>
            <th>Score</th>
            <th>HIGH</th>
            <th>MEDIUM</th>
            <th>Total Alerts</th>
        </tr>
        {% for entry in threat_summary %}
        <tr>
            <td>{{ entry.ip }}</td>
            <td><span class="badge {{ entry.threat_level }}">{{ entry.threat_level }}</span></td>
            <td>{{ entry.score }}</td>
            <td class="HIGH">{{ entry.HIGH }}</td>
            <td class="MEDIUM">{{ entry.MEDIUM }}</td>
            <td>{{ entry.total_alerts }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    <!-- Alert Log -->
    <h2>Alert Log</h2>
    {% if alerts %}
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Source IP</th>
            <th>Message</th>
        </tr>
        {% for alert in alerts|reverse %}
        <tr>
            <td>{{ alert.detected_at[:19].replace('T',' ') }}</td>
            <td>{{ alert.type }}</td>
            <td><span class="badge {{ alert.severity }}">{{ alert.severity }}</span></td>
            <td>{{ alert.src_ip }}</td>
            <td>{{ alert.message }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p style="color:#8b949e">No alerts generated yet. Run the detectors first.</p>
    {% endif %}

    <p class="footer">NetWatch · José Rafael Parra Dugarte · GRIAL Research Group · {{ now }}</p>
</body>
</html>
"""


@app.route("/")
def index():
    alerts  = load_alerts()
    report  = load_report()

    high_count   = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium_count = sum(1 for a in alerts if a.get("severity") == "MEDIUM")

    return render_template_string(
        TEMPLATE,
        alerts          = alerts,
        total_alerts    = len(alerts),
        high_count      = high_count,
        medium_count    = medium_count,
        total_ips       = report.get("total_ips", 0),
        threat_summary  = report.get("threat_summary", []),
        now             = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


@app.route("/api/alerts")
def api_alerts():
    return jsonify(load_alerts())


@app.route("/api/report")
def api_report():
    return jsonify(load_report())


if __name__ == "__main__":
    print("[NetWatch] Dashboard corriendo en http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
