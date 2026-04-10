total_packets = 0
encrypted_packets = 0
alerts_count = 0

ip_activity = {}
ip_alerts = {}   # ✅ NEW: track alerts per IP

# ==============================
# Update Functions
# ==============================

def update_packet_count():
    global total_packets
    total_packets += 1

def update_encrypted_count():
    global encrypted_packets
    encrypted_packets += 1

def update_ip_activity(ip):
    global ip_activity
    ip_activity[ip] = ip_activity.get(ip, 0) + 1

# ✅ UPDATED: track alerts per IP
def update_alert_count(ip=None):
    global alerts_count, ip_alerts
    alerts_count += 1

    if ip:
        ip_alerts[ip] = ip_alerts.get(ip, 0) + 1


# ==============================
# Getter Functions
# ==============================

def get_total_packets():
    return total_packets

def get_encrypted_packets():
    return encrypted_packets

def get_alerts_count():
    return alerts_count

# ✅ UPDATED: return most dangerous IP
def get_top_ip():
    if not ip_alerts:
        return "None"
    return max(ip_alerts, key=ip_alerts.get)


# ==============================
# 🔥 Network Status Engine
# ==============================

def get_network_status():
    if alerts_count >= 10:
        return "CRITICAL"
    elif alerts_count >= 4:
        return "ALERT"
    else:
        return "SAFE"