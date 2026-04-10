from scapy.all import sniff, IP, TCP, UDP
import detector
import stats


from tls_fingerprint import extract_tls_fingerprint


def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        source_ip = ip_layer.src
        packet_size = len(packet)

        stats.update_packet_count()
        stats.update_ip_activity(source_ip)

        
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            dest_port = tcp_layer.dport

            
            if dest_port in [443, 8443, 993, 995]:
                stats.update_encrypted_count()

               
                fingerprint = extract_tls_fingerprint(packet)

                if fingerprint:
                    detector.process_tls_fingerprint(
                        source_ip,
                        fingerprint["hash"],
                        fingerprint["ja3"]
                    )

         
            detector.detect_port_scan(
                source_ip,
                dest_port,
                packet_size
            )

      
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            dest_port = udp_layer.dport

            if dest_port == 443:  
                stats.update_encrypted_count()

               
                fingerprint = extract_tls_fingerprint(packet)

                if fingerprint:
                    detector.process_tls_fingerprint(
                        source_ip,
                        fingerprint["hash"],
                        fingerprint["ja3"]
                    )

    except Exception as e:
        print("Packet processing error:", e)


def start_sniffing(interface=None):
    print("🚀 IDS Started - Monitoring Network Traffic...\n")

    sniff(
        iface=interface,
        prn=process_packet,
        store=False
    )