import sqlite3
import json
from datetime import datetime


def init_parsed_table(db_path="siem.db"):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parsed_events (
            event_id    TEXT PRIMARY KEY,
            timestamp   TEXT,
            source      TEXT,
            event_type  TEXT,
            host        TEXT,
            pid         INTEGER,
            process     TEXT,
            username    TEXT,
            local_ip    TEXT,
            local_port  INTEGER,
            remote_ip   TEXT,
            remote_port INTEGER,
            status      TEXT
        )
    """)
    conn.commit()
    conn.close()


def parse_events(db_path="siem.db"):
    conn = sqlite3.connect(db_path)

    # Henuz parse edilmeyenleri al
    rows = conn.execute("""
        SELECT e.event_id, e.source, e.event_type, e.timestamp, e.host, e.data
        FROM events e
        LEFT JOIN parsed_events p ON e.event_id = p.event_id
        WHERE p.event_id IS NULL
    """).fetchall()

    if not rows:
        print("[Parser] No new events to parse.")
        conn.close()
        return

    parsed = []
    for row in rows:
        event_id, source, event_type, timestamp, host, data_str = row
        data = json.loads(data_str)

        parsed.append((
            event_id,
            timestamp,
            source,
            event_type,
            host,
            data.get('pid'),
            data.get('name') or data.get('process'),
            data.get('username'),
            data.get('local_ip'),
            data.get('local_port'),
            data.get('remote_ip'),
            data.get('remote_port'),
            data.get('status')
        ))

    conn.executemany("""
        INSERT OR IGNORE INTO parsed_events VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, parsed)
    conn.commit()
    conn.close()

    print(f"[Parser] {len(parsed)} events parsed.")


init_parsed_table()
parse_events()