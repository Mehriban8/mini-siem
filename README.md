# Mini-SIEM

A lightweight Security Information and Event Management (SIEM) system for Windows, built from scratch in Python.

## What it does

- Collects running processes and network connections every 60 seconds
- Parses and normalizes collected data
- Detects suspicious activity using configurable rules
- Sends Windows notifications on alerts
- Displays everything on a real-time dashboard

## Dashboard features

- Live stats (events, alerts, processes, connections)
- Alert severity chart
- Process inspector — click any process to see details
- Alert history with severity filter
- Export alerts to CSV
- Browser notifications for new alerts

## Quick start

```bash
git clone https://github.com/Mehriban8/mini-siem
cd mini-siem
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Open `http://localhost:5000` in your browser.

## Tech stack

- Python 3.x
- psutil — process and network collection
- SQLite — local data storage
- Flask — dashboard backend
- Chart.js — visualizations
- YAML — rule configuration

## Adding custom rules

Edit `config/rules.yaml` — no code changes needed.