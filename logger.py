import json
from datetime import datetime
import time
import uuid
import os

last_logged = {}
COOLDOWN = 10  # seconds
LOG_FILE = "logs.txt"
MAX_LOG_SIZE = 5_000_000  # 5MB


def log_event(event_type, source_ip, risk_score, location=None, extra=None):

    now = time.time()
    key = f"{source_ip}_{event_type}"

    # 🔥 smarter cooldown
    if key in last_logged:
        if now - last_logged[key] < COOLDOWN:
            return
    last_logged[key] = now

    # 🔥 ensure valid risk score
    try:
        risk_score = int(risk_score)
    except:
        risk_score = 0

    # 🔥 severity classification
    if risk_score >= 70:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    log_entry = {
        "log_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "risk_score": risk_score,
        "severity": severity,
        "log_source": "IDS_ENGINE"
    }

    # ✅ improved location handling
    if location and location.get("lat") is not None:
        log_entry["location"] = location
        log_entry["network_type"] = "EXTERNAL"
    else:
        log_entry["location"] = None
        log_entry["network_type"] = "INTERNAL"

    # 🔥 flatten extra fields safely
    if extra and isinstance(extra, dict):
        log_entry.update(extra)

    try:
        # 🔥 safe log rotation
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
            backup_name = f"logs_{int(time.time())}.txt"
            os.rename(LOG_FILE, backup_name)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

    except Exception as e:
        print("Logging error:", e)