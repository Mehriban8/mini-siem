import sqlite3
import json
from flask import Flask, render_template, jsonify
from flask import Flask, render_template, jsonify, request
app = Flask(__name__)
DB_PATH = "siem.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")
@app.route("/api/process/<name>")
def process_detail(name):
    conn = get_db()
    
    stats = conn.execute("""
        SELECT 
            process,
            COUNT(*) as seen_count,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen,
            username
        FROM parsed_events
        WHERE process = ? AND source = 'process'
        GROUP BY process, username
    """, (name,)).fetchone()

    connections = conn.execute("""
        SELECT DISTINCT remote_ip, remote_port, status
        FROM parsed_events
        WHERE process = ? AND source = 'network'
        AND remote_ip IS NOT NULL
    """, (name,)).fetchall()

    alerts = conn.execute("""
        SELECT rule_name, severity, timestamp
        FROM alerts
        WHERE process = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (name,)).fetchall()

    conn.close()

    if not stats:
        return jsonify({"error": "Process not found"}), 404

    return jsonify({
        "process":    stats["process"],
        "seen_count": stats["seen_count"],
        "first_seen": stats["first_seen"],
        "last_seen":  stats["last_seen"],
        "username":   stats["username"],
        "connections": [dict(r) for r in connections],
        "alerts":     [dict(r) for r in alerts]
    })

@app.route("/api/stats")
def stats():
    conn = get_db()
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    total_processes = conn.execute(
        "SELECT COUNT(*) FROM parsed_events WHERE source='process'"
    ).fetchone()[0]
    total_connections = conn.execute(
        "SELECT COUNT(*) FROM parsed_events WHERE source='network'"
    ).fetchone()[0]
    conn.close()
    return jsonify({
        "total_events": total_events,
        "total_alerts": total_alerts,
        "total_processes": total_processes,
        "total_connections": total_connections
    })

@app.route("/api/alerts/history")
def alerts_history():
    severity = request.args.get('severity', '')
    conn = get_db()
    
    if severity:
        rows = conn.execute("""
            SELECT alert_id, rule_id, rule_name, severity, process,
                   remote_ip, remote_port, timestamp, description
            FROM alerts
            WHERE severity = ?
            ORDER BY timestamp DESC
        """, (severity,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT alert_id, rule_id, rule_name, severity, process,
                   remote_ip, remote_port, timestamp, description
            FROM alerts
            ORDER BY timestamp DESC
        """).fetchall()
    
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts")
def alerts():
    conn = get_db()
    rows = conn.execute("""
        SELECT alert_id, rule_id, rule_name, severity, process, 
               remote_ip, remote_port, timestamp, description
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 20
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/severity")
def severity():
    conn = get_db()
    rows = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

import csv
import io
from flask import Response

@app.route("/api/export/alerts")
def export_alerts():
    conn = get_db()
    rows = conn.execute("""
        SELECT alert_id, rule_id, rule_name, severity, process,
               remote_ip, remote_port, timestamp, description
        FROM alerts
        ORDER BY timestamp DESC
    """).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["alert_id", "rule_id", "rule_name", "severity",
                     "process", "remote_ip", "remote_port", "timestamp", "description"])
    for row in rows:
        writer.writerow(list(row))

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"}
    )

@app.route("/api/top_processes")
def top_processes():
    conn = get_db()
    rows = conn.execute("""
        SELECT process, COUNT(*) as count
        FROM parsed_events
        WHERE source='process' AND process IS NOT NULL AND process != ''
        GROUP BY process
        ORDER BY count DESC
        LIMIT 8
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


import socket as sock

@app.route("/api/connections")
def connections():
    conn = get_db()
    rows = conn.execute("""
        SELECT DISTINCT process, remote_ip, remote_port, status
        FROM parsed_events
        WHERE source='network' AND remote_ip IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 10
    """).fetchall()
    conn.close()

    result = []
    for r in rows:
        domain = ""
        try:
            domain = sock.gethostbyaddr(r["remote_ip"])[0]
        except Exception:
            domain = ""
        result.append({
            "process":     r["process"],
            "remote_ip":   r["remote_ip"],
            "remote_port": r["remote_port"],
            "status":      r["status"],
            "domain":      domain
        })

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)