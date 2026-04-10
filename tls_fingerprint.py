from scapy.all import TCP, Raw
import hashlib


def extract_tls_fingerprint(packet):
    try:
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]

        if tcp.dport not in [443, 8443]:
            return None

        if not packet.haslayer(Raw):
            return None

        payload = bytes(packet[Raw].load)

        
        if b'\x16\x03' not in payload:
            return None

       
        version = payload[1:3] if len(payload) > 3 else b'\x00\x00'

        sample = payload[:40]

       
        fingerprint_str = str(version) + str(sample)

       
        fingerprint_hash = hashlib.md5(fingerprint_str.encode()).hexdigest()

        return {
            "ja3": fingerprint_str,
            "hash": fingerprint_hash
        }

    except Exception:
        return None