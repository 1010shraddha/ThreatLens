import csv
import os
from geo import get_ip_location   # 🔥 your existing geo function

FILE_NAME = "flow_dataset.csv"

def init_csv():
    if not os.path.exists(FILE_NAME):
        with open(FILE_NAME, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "source_ip",
                "country",
                "city",
                "org",
                "packet_count",
                "byte_count",
                "duration",
                "avg_packet_size",
                "unique_ports",
                "risk_score",
                "label"
            ])

def log_flow(source_ip, flow, risk_score):

    # 🔥 GET LOCATION (CACHED)
    location = get_ip_location(source_ip)

    # 🔥 BETTER LABEL LOGIC
    if risk_score > 70:
        label = "ATTACK"
    elif risk_score > 40:
        label = "SUSPICIOUS"
    else:
        label = "NORMAL"

    with open(FILE_NAME, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            source_ip,
            location.get("country", "Unknown"),
            location.get("city", "Unknown"),
            location.get("org", "Unknown"),
            flow.get("packet_count", 0),
            flow.get("byte_count", 0),
            flow.get("duration", 0),
            flow.get("avg_packet_size", 0),
            flow.get("unique_ports", 0),
            risk_score,
            label
        ])