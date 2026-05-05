import sqlite3
import json
import uuid
import yaml
from datetime import datetime


def load_rules(path="config/rules.yaml"):
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    return config.get("rules", [])


def init_alerts_table(db_path="siem.db"):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id    TEXT PRIMARY KEY,
            rule_id     TEXT,
            rule_name   TEXT,
            severity    TEXT,
            event_id    TEXT,
            timestamp   TEXT,
            description TEXT,
            process     TEXT,
            remote_ip   TEXT,
            remote_port INTEGER
        )
    """)
    conn.commit()
    conn.close()


def check_condition(condition, event):
    field = condition["field"]
    value = event.get(field)

    if condition["type"] == "match":
        return value in condition["values"]

    elif condition["type"] == "greater_than":
        if value is None:
            return False
        return int(value) > int(condition["value"])

    return False


def run_engine(db_path="siem.db"):
    rules = load_rules()
    print(f"[Rule Engine] {len(rules)} rules loaded.")

    conn = sqlite3.connect(db_path)

    # Henuz yoxlanilmamis parsed eventleri al
    rows = conn.execute("""
        SELECT p.event_id, p.source, p.event_type, p.timestamp,
               p.host, p.process, p.username,
               p.local_ip, p.local_port,
               p.remote_ip, p.remote_port, p.status
        FROM parsed_events p
        LEFT JOIN alerts a ON p.event_id = a.event_id
        WHERE a.event_id IS NULL
    """).fetchall()

    print(f"[Rule Engine] {len(rows)} events to check.")

    alerts = []
    for row in rows:
        event = {
            "event_id":   row[0],
            "source":     row[1],
            "event_type": row[2],
            "timestamp":  row[3],
            "host":       row[4],
            "process":    row[5],
            "username":   row[6],
            "local_ip":   row[7],
            "local_port": row[8],
            "remote_ip":  row[9],
            "remote_port":row[10],
            "status":     row[11]
        }

        for rule in rules:
            # Source uygunlugunu yoxla
            if rule.get("source") and rule["source"] != event["source"]:
                continue

            # Condition yoxla
            if check_condition(rule["condition"], event):
                alert = (
                    str(uuid.uuid4()),
                    rule["id"],
                    rule["name"],
                    rule["severity"],
                    event["event_id"],
                    datetime.now().isoformat(),
                    rule["description"],
                    event.get("process"),
                    event.get("remote_ip"),
                    event.get("remote_port")
                )
                alerts.append(alert)
                print(f"[ALERT] {rule['severity'].upper()} — "
                      f"{rule['name']} — {event.get('process')}")

    if alerts:
        conn.executemany("""
            INSERT OR IGNORE INTO alerts VALUES
            (?,?,?,?,?,?,?,?,?,?)
        """, alerts)
        conn.commit()
        print(f"[Rule Engine] {len(alerts)} alerts saved.")
    else:
        print("[Rule Engine] No alerts triggered.")

    conn.close()


init_alerts_table()
run_engine()