import threading
import os
from packet_sniffer import start_sniffing
from dataset_logger import init_csv
from app import app

# =========================
# INITIAL SETUP
# =========================

init_csv()  # ensure CSV exists

# 🔥 NEW: Clear UI logs (keeps dashboard fresh)
if os.path.exists("logs.txt"):
    open("logs.txt", "w").close()

# =========================
# IDS START FUNCTION
# =========================

def start_ids():
    print("🚀 IDS Started - Monitoring Network Traffic...\n")
    start_sniffing()

# =========================
# MAIN ENTRY
# =========================

if __name__ == "__main__":
    print("🔥 Starting Encrypted Traffic Behavioral IDS + Web Dashboard...\n")

    # ✅ Prevent duplicate execution (Flask debug issue fix)
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        sniff_thread = threading.Thread(target=start_ids)
        sniff_thread.daemon = True
        sniff_thread.start()

    # Start Flask server
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)