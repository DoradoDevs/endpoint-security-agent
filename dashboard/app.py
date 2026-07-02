"""
Sentinel Dashboard — Web Application

Flask-based web server for the fleet management dashboard.
Provides both REST API endpoints and an HTML dashboard UI.

Usage:
    python -m dashboard.app                    # Start on default port 5000
    python -m dashboard.app --port 8080        # Custom port
    python -m dashboard.app --host 0.0.0.0     # Listen on all interfaces

Flask is an optional dependency. The dashboard API (dashboard.api) works
independently for programmatic use without Flask.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.logging import get_logger

log = get_logger()


def create_app(db_path: Path | None = None):
    """Create and configure the Flask application."""
    try:
        from flask import Flask, request, jsonify, render_template_string
    except ImportError:
        log.error(
            "Flask is required for the dashboard. "
            "Install it with: pip install flask"
        )
        raise SystemExit(1)

    from dashboard.api import DashboardAPI
    from dashboard.models import DashboardDB

    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    db = DashboardDB(db_path)
    api = DashboardAPI(db)

    # === REST API Routes ===

    @app.route("/api/v1/devices/enroll", methods=["POST"])
    def enroll_device():
        data = request.get_json(force=True)
        result, status = api.enroll_device(data)
        return jsonify(result), status

    @app.route("/api/v1/devices", methods=["GET"])
    def list_devices():
        status_filter = request.args.get("status", "")
        result, status = api.list_devices(status=status_filter)
        return jsonify(result), status

    @app.route("/api/v1/devices/<device_id>", methods=["GET"])
    def get_device(device_id: str):
        result, status = api.get_device(device_id)
        return jsonify(result), status

    @app.route("/api/v1/devices/<device_id>", methods=["DELETE"])
    def remove_device(device_id: str):
        result, status = api.remove_device(device_id)
        return jsonify(result), status

    @app.route("/api/v1/devices/<device_id>/history", methods=["GET"])
    def device_history(device_id: str):
        limit = request.args.get("limit", 50, type=int)
        result, status = api.get_device_history(device_id, limit=limit)
        return jsonify(result), status

    @app.route("/api/v1/devices/<device_id>/policy", methods=["GET"])
    def device_policy(device_id: str):
        result, status = api.get_device_policy(device_id)
        return jsonify(result), status

    @app.route("/api/v1/telemetry/submit", methods=["POST"])
    def submit_telemetry():
        data = request.get_json(force=True)
        result, status = api.submit_telemetry(data)
        return jsonify(result), status

    @app.route("/api/v1/fleet/summary", methods=["GET"])
    def fleet_summary():
        result, status = api.get_fleet_summary()
        return jsonify(result), status

    @app.route("/api/v1/scans/recent", methods=["GET"])
    def recent_scans():
        limit = request.args.get("limit", 100, type=int)
        result, status = api.get_recent_scans(limit=limit)
        return jsonify(result), status

    @app.route("/api/v1/policies", methods=["POST"])
    def create_policy():
        data = request.get_json(force=True)
        result, status = api.create_policy(data)
        return jsonify(result), status

    @app.route("/api/v1/policies/assign", methods=["POST"])
    def assign_policy():
        data = request.get_json(force=True)
        result, status = api.assign_policy(data)
        return jsonify(result), status

    # === Dashboard UI Routes ===

    @app.route("/")
    def dashboard_home():
        summary_data, _ = api.get_fleet_summary()
        devices_data, _ = api.list_devices()
        return render_template_string(
            DASHBOARD_TEMPLATE,
            summary=summary_data["summary"],
            devices=devices_data["devices"],
        )

    @app.route("/device/<device_id>")
    def device_detail(device_id: str):
        device_data, status = api.get_device(device_id)
        if status != 200:
            return f"Device not found: {device_id}", 404
        history_data, _ = api.get_device_history(device_id, limit=20)
        return render_template_string(
            DEVICE_TEMPLATE,
            device=device_data["device"],
            scans=history_data["scans"],
        )

    return app


# === Inline Templates ===
# Simple HTML templates for the dashboard UI.

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Sentinel Fleet Dashboard</title>
    <style>
        body { font-family: -apple-system, sans-serif; margin: 0; padding: 20px;
               background: #0d1117; color: #c9d1d9; }
        .header { text-align: center; padding: 20px; }
        .header h1 { color: #58a6ff; margin: 0; }
        .header p { color: #8b949e; }
        .stats { display: flex; gap: 20px; justify-content: center; margin: 20px 0; }
        .stat-card { background: #161b22; border: 1px solid #30363d;
                     border-radius: 8px; padding: 20px; text-align: center; min-width: 150px; }
        .stat-card .value { font-size: 2em; font-weight: bold; color: #58a6ff; }
        .stat-card .label { color: #8b949e; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px;
                background: #161b22; border-radius: 8px; overflow: hidden; }
        th { background: #21262d; color: #58a6ff; padding: 12px; text-align: left; }
        td { padding: 10px 12px; border-top: 1px solid #30363d; }
        tr:hover { background: #1c2128; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .grade-a { color: #3fb950; } .grade-b { color: #d29922; }
        .grade-c { color: #d29922; } .grade-d { color: #f85149; }
        .grade-f { color: #f85149; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SENTINEL Fleet Dashboard</h1>
        <p>Centralized Security Monitoring</p>
    </div>
    <div class="stats">
        <div class="stat-card">
            <div class="value">{{ summary.total_devices }}</div>
            <div class="label">Total Devices</div>
        </div>
        <div class="stat-card">
            <div class="value">{{ summary.active_devices }}</div>
            <div class="label">Active</div>
        </div>
        <div class="stat-card">
            <div class="value">{{ summary.average_risk_score }}/100</div>
            <div class="label">Avg Risk Score</div>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Hostname</th><th>OS</th><th>Version</th>
                <th>Risk Score</th><th>Grade</th><th>Last Scan</th><th>Status</th>
            </tr>
        </thead>
        <tbody>
        {% for device in devices %}
            <tr>
                <td><a href="/device/{{ device.device_id }}">{{ device.hostname }}</a></td>
                <td>{{ device.os_name }}</td>
                <td>{{ device.agent_version }}</td>
                <td>{{ device.last_risk_score }}/100</td>
                <td class="grade-{{ device.last_risk_grade|lower }}">{{ device.last_risk_grade }}</td>
                <td>{{ device.last_scan[:19] if device.last_scan else 'Never' }}</td>
                <td>{{ device.status }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
</body>
</html>"""

DEVICE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>{{ device.hostname }} — Sentinel</title>
    <style>
        body { font-family: -apple-system, sans-serif; margin: 0; padding: 20px;
               background: #0d1117; color: #c9d1d9; }
        h1 { color: #58a6ff; }
        h2 { color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
        .info-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
        .info-item { background: #161b22; border: 1px solid #30363d;
                     border-radius: 6px; padding: 12px; }
        .info-item .label { color: #8b949e; font-size: 0.85em; }
        .info-item .value { font-size: 1.1em; margin-top: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 16px;
                background: #161b22; border-radius: 8px; overflow: hidden; }
        th { background: #21262d; color: #58a6ff; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-top: 1px solid #30363d; }
        a { color: #58a6ff; text-decoration: none; }
    </style>
</head>
<body>
    <p><a href="/">← Back to Dashboard</a></p>
    <h1>{{ device.hostname }}</h1>
    <div class="info-grid">
        <div class="info-item">
            <div class="label">Device ID</div>
            <div class="value">{{ device.device_id }}</div>
        </div>
        <div class="info-item">
            <div class="label">OS</div>
            <div class="value">{{ device.os_name }} {{ device.os_version }}</div>
        </div>
        <div class="info-item">
            <div class="label">Agent Version</div>
            <div class="value">{{ device.agent_version }}</div>
        </div>
        <div class="info-item">
            <div class="label">Risk Score</div>
            <div class="value">{{ device.last_risk_score }}/100 ({{ device.last_risk_grade }})</div>
        </div>
        <div class="info-item">
            <div class="label">Status</div>
            <div class="value">{{ device.status }}</div>
        </div>
        <div class="info-item">
            <div class="label">Enrolled</div>
            <div class="value">{{ device.enrolled_at[:19] if device.enrolled_at else 'N/A' }}</div>
        </div>
    </div>
    <h2>Scan History</h2>
    <table>
        <thead>
            <tr><th>Timestamp</th><th>Score</th><th>Grade</th><th>Findings</th><th>Scanners</th></tr>
        </thead>
        <tbody>
        {% for scan in scans %}
            <tr>
                <td>{{ scan.timestamp[:19] }}</td>
                <td>{{ scan.risk_score }}/100</td>
                <td>{{ scan.risk_grade }}</td>
                <td>{{ scan.findings_count }}</td>
                <td>{{ scan.scanners_run|length }} scanners</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Sentinel Fleet Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--db", type=str, default=None, help="Database file path")
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else None
    app = create_app(db_path=db_path)

    print(f"Sentinel Fleet Dashboard starting on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
