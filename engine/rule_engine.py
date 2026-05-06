import sqlite3
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