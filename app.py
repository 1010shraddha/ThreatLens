from flask import Flask, jsonify, render_template
import stats
import detector
import json
import os

import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)

# =========================
# EMAIL FUNCTION (UPDATED ONLY)
# =========================
def send_alert_email():

    sender = ""
    receiver = ""
    password = "hwaddtadojknpbbb"

    # ✅ GET LATEST LOG DETAILS
    latest_log = None
    try:
        if os.path.exists("logs.txt"):
            with open("logs.txt", "r") as f:
                lines = f.readlines()
                if lines:
                    latest_log = json.loads(lines[-1])
    except:
        pass

    # ✅ SAFE EXTRACTION
    ip = latest_log.get("source_ip", "Unknown") if latest_log else "Unknown"
    attack = latest_log.get("event_type", "Unknown") if latest_log else "Unknown"
    risk = latest_log.get("risk_score", "Unknown") if latest_log else "Unknown"
    time = latest_log.get("timestamp", "Unknown") if latest_log else "Unknown"

    # 🔥 DETAILED MESSAGE
    message = f"""
🚨 ThreatLens CRITICAL ALERT 🚨

Attack Detected!

🔹 IP Address: {ip}
🔹 Attack Type: {attack}
🔹 Risk Score: {risk}
🔹 Time: {time}

⚠ Immediate action required.
"""

    msg = MIMEText(message)
    msg["Subject"] = "🚨 ThreatLens Alert"
    msg["From"] = sender
    msg["To"] = receiver

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
        print("✅ Alert email sent")
    except Exception as e:
        print("❌ Email error:", e)


# =========================
# HOME ROUTE
# =========================

@app.route("/")
def index():
    return render_template("dashboard.html")


# =========================
# API: STATS
# =========================

@app.route("/api/stats")
def get_stats():
    total_packets = stats.get_total_packets()
    encrypted_packets = stats.get_encrypted_packets()
    alerts = stats.get_alerts_count()
    status = stats.get_network_status()

    # 🚨 SEND EMAIL ON CRITICAL (UNCHANGED LOGIC)
    if status == "CRITICAL":
        send_alert_email()

    encryption_ratio = 0
    if total_packets > 0:
        encryption_ratio = (encrypted_packets / total_packets) * 100

    return jsonify({
        "total_packets": total_packets,
        "encrypted_packets": encrypted_packets,
        "alerts": alerts,
        "encryption_ratio": round(encryption_ratio, 2),
        "status": status,
        "top_ip": stats.get_top_ip(),
        "suspicious_ips": list(detector.get_suspicious_ips())
    })


# =========================
# API: LOGS (UPDATED)
# =========================

@app.route("/logs")
def get_logs():
    logs = []

    try:
        if os.path.exists("logs.txt"):
            with open("logs.txt", "r") as f:
                for line in f:
                    try:
                        logs.append(json.loads(line.strip()))
                    except:
                        continue

        # 🔥 Sort latest first
        logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)

        # ✅ REMOVED LIMIT (IMPORTANT FIX)
        # logs = logs[:20]

    except Exception as e:
        print("Log read error:", e)

    return jsonify(logs)


# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
