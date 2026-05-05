import sqlite3
import time
from datetime import datetime
from plyer import notification


def check_alerts(db_path="siem.db"):
    conn = sqlite3.connect(db_path)
    
    
    rows = conn.execute("""
        SELECT alert_id, rule_name, severity, process, remote_ip, remote_port
        FROM alerts
        WHERE timestamp >= datetime('now', '-60 seconds')
    """).fetchall()
    
    conn.close()
    return rows


def send_notification(rule_name, severity, process, remote_ip, remote_port):
   
    details = process or remote_ip or "unknown"
    
    notification.notify(
        title=f"[{severity.upper()}] {rule_name}",
        message=f"Detected: {details}",
        app_name="Mini-SIEM",
        timeout=10
    )


def run_alerter(interval=30):
    print("[Alerter] Started — checking every 30 seconds...")
    
    seen = set()  
    
    while True:
        alerts = check_alerts()
        
        for alert in alerts:
            alert_id, rule_name, severity, process, remote_ip, remote_port = alert
            
            if alert_id not in seen:
                seen.add(alert_id)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"ALERT — {severity.upper()} — {rule_name} — {process or remote_ip}")
                send_notification(rule_name, severity, process, remote_ip, remote_port)
        
        time.sleep(interval)


run_alerter()