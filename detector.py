import time
from collections import defaultdict
from logger import log_event
import stats
import json
from geo import get_ip_location
from dataset_logger import log_flow

# ==============================
# Load Configuration
# ==============================

with open("config.json") as f:
    config = json.load(f)

PORT_THRESHOLD = config["PORT_THRESHOLD"]
TIME_WINDOW = config["TIME_WINDOW"]
RISK_LIMIT = config["RISK_LIMIT"]
RISK_DECAY_TIME = config["RISK_DECAY_TIME"]
RISK_INCREMENT = config["RISK_INCREMENT"]
RISK_DECAY_VALUE = config["RISK_DECAY_VALUE"]
RATE_WINDOW = config["RATE_WINDOW"]
PACKET_RATE_THRESHOLD = config["PACKET_RATE_THRESHOLD"]

MAX_RISK = 100
LOG_COOLDOWN = 5

# ✅ UPDATED WHITELIST (IMPORTANT FIX)
WHITELIST = [
    "127.0.0.1",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20."
]

# ==============================
# Data Structures
# ==============================

port_activity = defaultdict(list)
packet_activity = defaultdict(list)

flow_data = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "ports": set(),
    "first_seen": time.time(),
    "last_seen": time.time()
})

risk_scores = defaultdict(int)
suspicious_ips = set()
last_activity_time = defaultdict(lambda: time.time())
last_logged_time = defaultdict(lambda: 0)

baseline_stats = defaultdict(lambda: {
    "avg_rate": 0,
    "avg_ports": 0,
    "samples": 0
})

tls_fingerprints = {}
known_fingerprints = set()

# ==============================
# Utility
# ==============================

def apply_risk_decay(source_ip, current_time):
    if current_time - last_activity_time[source_ip] > RISK_DECAY_TIME:
        risk_scores[source_ip] = max(0, risk_scores[source_ip] - RISK_DECAY_VALUE)
        last_activity_time[source_ip] = current_time


def classify_attack(flow, packet_rate):
    if packet_rate > 100:
        return "DOS_ATTACK"

    if flow["unique_ports"] > 20:
        return "AGGRESSIVE_PORT_SCAN"

    if flow["unique_ports"] > 10:
        return "MODERATE_PORT_SCAN"

    if flow["unique_ports"] > 3:
        return "PORT_SCAN"

    if flow["avg_packet_size"] < 200:
        return "SMALL_PACKET_ATTACK"

    return "SUSPICIOUS_ACTIVITY"

# ==============================
# TLS Processing
# ==============================

def process_tls_fingerprint(source_ip, fp_hash, ja3):

    tls_fingerprints[source_ip] = {
        "hash": fp_hash,
        "ja3": ja3
    }

    if fp_hash not in known_fingerprints:
        if source_ip in suspicious_ips:
            risk_scores[source_ip] += 1

    known_fingerprints.add(fp_hash)

# ==============================
# Main Detection
# ==============================

def detect_port_scan(source_ip, dest_port, packet_size):

    # 🔥 Skip trusted IPs
    for trusted in WHITELIST:
        if source_ip.startswith(trusted):
            return

    current_time = time.time()
    apply_risk_decay(source_ip, current_time)

    flow = flow_data[source_ip]

    # Flow update
    flow["packet_count"] += 1
    flow["byte_count"] += packet_size
    flow["ports"].add(dest_port)
    flow["last_seen"] = current_time

    flow["duration"] = flow["last_seen"] - flow["first_seen"]
    flow["avg_packet_size"] = flow["byte_count"] / flow["packet_count"]
    flow["unique_ports"] = len(flow["ports"])

    # Port tracking
    port_activity[source_ip].append((dest_port, current_time))
    last_activity_time[source_ip] = current_time

    port_activity[source_ip] = [
        (port, t)
        for port, t in port_activity[source_ip]
        if current_time - t <= TIME_WINDOW
    ]

    unique_ports = set(port for port, _ in port_activity[source_ip])

    # Packet rate
    packet_activity[source_ip].append(current_time)
    packet_activity[source_ip] = [
        t for t in packet_activity[source_ip]
        if current_time - t <= RATE_WINDOW
    ]

    packet_rate = len(packet_activity[source_ip])
    attack_type = None

    # ==============================
    # Baseline Learning
    # ==============================

    base = baseline_stats[source_ip]
    base["samples"] += 1

    base["avg_rate"] = (
        (base["avg_rate"] * (base["samples"] - 1) + packet_rate)
        / base["samples"]
    )

    base["avg_ports"] = (
        (base["avg_ports"] * (base["samples"] - 1) + len(unique_ports))
        / base["samples"]
    )

    # ==============================
    # Smart Detection
    # ==============================

    if packet_rate > base["avg_rate"] * 3 and flow["packet_count"] > 25:
        risk_scores[source_ip] += 4
        attack_type = "TRAFFIC_SPIKE"

    if len(unique_ports) > base["avg_ports"] * 3:
        risk_scores[source_ip] += 4
        attack_type = "PORT_ANOMALY"

    if flow["duration"] < 2 and flow["packet_count"] > 40:
        risk_scores[source_ip] += 5
        attack_type = "BURST_ATTACK"

    if flow["duration"] > 30 and flow["unique_ports"] > 10:
        risk_scores[source_ip] += 3
        attack_type = "SLOW_SCAN"

    if packet_rate > PACKET_RATE_THRESHOLD and flow["packet_count"] > 25:
        risk_scores[source_ip] += 3
        attack_type = "HIGH_PACKET_RATE"

    if len(unique_ports) >= PORT_THRESHOLD:
        risk_scores[source_ip] += 2
        attack_type = classify_attack(flow, packet_rate)

    risk_scores[source_ip] = min(risk_scores[source_ip], MAX_RISK)

    # 🔥 Noise filter
    if risk_scores[source_ip] < 10:
        return

    # ==============================
    # FINAL ALERT
    # ==============================

    if attack_type:

        if current_time - last_logged_time[source_ip] > LOG_COOLDOWN:

            # ✅ CRITICAL FIX
            stats.update_alert_count(source_ip)

            print(f"\n🚨 {attack_type} from {source_ip} | Risk: {risk_scores[source_ip]}")

            location = get_ip_location(source_ip)

            if not location:
                location = {
                    "ip": source_ip,
                    "city": "Unknown",
                    "country": "Unknown",
                    "org": "Unknown",
                    "lat": 20.5937,
                    "lon": 78.9629
                }

            if risk_scores[source_ip] >= RISK_LIMIT and flow["packet_count"] > 20:
                suspicious_ips.add(source_ip)

            log_event(
                attack_type,
                source_ip,
                risk_scores[source_ip],
                location=location,
                extra={
                    "packet_rate": packet_rate,
                    "packet_count": flow["packet_count"],
                    "unique_ports": flow["unique_ports"],
                    "is_suspicious": source_ip in suspicious_ips
                }
            )

            last_logged_time[source_ip] = current_time

        log_flow(source_ip, flow, risk_scores[source_ip])

# ==============================
# Accessors
# ==============================

def get_suspicious_ips():
    return list(suspicious_ips)