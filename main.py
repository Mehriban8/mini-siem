import time
import threading
import sqlite3
import json
import uuid
import socket
import psutil
from datetime import datetime
from engine.rule_engine import init_alerts_table, load_rules, check_condition
from parser import init_parsed_table, parse_events


DB_PATH = "siem.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, timestamp TEXT,
            source TEXT, event_type TEXT, host TEXT, data TEXT
        )
    """)
    conn.commit()
    conn.close()
    init_parsed_table()
    init_alerts_table()

def cleanup_old_data(db_path="siem.db", days=7):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        DELETE FROM events 
        WHERE timestamp < datetime('now', ? )
    """, (f'-{days} days',))
    conn.execute("""
        DELETE FROM parsed_events 
        WHERE timestamp < datetime('now', ?)
    """, (f'-{days} days',))
    conn.commit()
    conn.close()
    print(f"[Cleanup] Events older than {days} days deleted.")

def collect_and_process():
    while True:
        try:
            
            events = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    events.append({
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now().isoformat(),
                        "source": "process",
                        "event_type": "process_snapshot",
                        "host": socket.gethostname(),
                        "data": {
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "username": proc.info['username']
                        }
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status not in ('ESTABLISHED', 'LISTEN'):
                        continue
                    try:
                        proc_name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "unknown"
                    events.append({
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now().isoformat(),
                        "source": "network",
                        "event_type": "connection",
                        "host": socket.gethostname(),
                        "data": {
                            "pid": conn.pid,
                            "process": proc_name,
                            "local_ip": conn.laddr.ip if conn.laddr else None,
                            "local_port": conn.laddr.port if conn.laddr else None,
                            "remote_ip": conn.raddr.ip if conn.raddr else None,
                            "remote_port": conn.raddr.port if conn.raddr else None,
                            "status": conn.status
                        }
                    })
            except psutil.AccessDenied:
                pass

            
            db = sqlite3.connect(DB_PATH)
            for event in events:
                db.execute(
                    "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)",
                    (event["event_id"], event["timestamp"], event["source"],
                     event["event_type"], event["host"], json.dumps(event["data"]))
                )
            db.commit()
            db.close()

            
            parse_events(DB_PATH)

            
            rules = load_rules()
            db = sqlite3.connect(DB_PATH)
            rows = db.execute("""
                SELECT p.event_id, p.source, p.event_type, p.timestamp,
                       p.host, p.process, p.username,
                       p.local_ip, p.local_port,
                       p.remote_ip, p.remote_port, p.status
                FROM parsed_events p
                LEFT JOIN alerts a ON p.event_id = a.event_id
                WHERE a.event_id IS NULL
            """).fetchall()

            for row in rows:
                event = {
                    "event_id": row[0], "source": row[1],
                    "event_type": row[2], "timestamp": row[3],
                    "host": row[4], "process": row[5],
                    "username": row[6], "local_ip": row[7],
                    "local_port": row[8], "remote_ip": row[9],
                    "remote_port": row[10], "status": row[11]
                }
                for rule in rules:
                    if rule.get("source") and rule["source"] != event["source"]:
                        continue
                    if check_condition(rule["condition"], event):
                        db.execute(
                            "INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (str(uuid.uuid4()), rule["id"], rule["name"],
                             rule["severity"], event["event_id"],
                             datetime.now().isoformat(), rule["description"],
                             event.get("process"), event.get("remote_ip"),
                             event.get("remote_port"))
                        )
                        print(f"[ALERT] {rule['severity'].upper()} — "
                              f"{rule['name']} — {event.get('process')}")
            db.commit()
            db.close()

            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Cycle complete — {len(events)} events processed")

        except Exception as e:
            print(f"[Error] {e}")
        cleanup_old_data(days=7)

        time.sleep(60)


if __name__ == "__main__":
    init_db()
    print("[SIEM] Starting...")

    
    t = threading.Thread(target=collect_and_process, daemon=True)
    t.start()

    
    from dashboard.app import app
    app.run(debug=False, port=5000)