#task 5 network packet analyzer

import scapy.all as scapy

def extract_payload(packet, layer):
    try:
        payload = packet[scapy.Raw].load
        decoded_payload = payload.decode('utf-8', 'ignore')
        return decoded_payload
    except (IndexError, UnicodeDecodeError):
        return "Unable to decode payload."

def handle_ip_packet(packet):
    source_ip = packet[scapy.IP].src
    destination_ip = packet[scapy.IP].dst
    protocol = packet[scapy.IP].proto

    print(f"Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol}")

    if packet.haslayer(scapy.TCP):
        tcp_payload = extract_payload(packet, scapy.TCP)
        print(f"TCP Payload: {tcp_payload}")
    elif packet.haslayer(scapy.UDP):
        udp_payload = extract_payload(packet, scapy.UDP)
        print(f"UDP Payload: {udp_payload}")

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        handle_ip_packet(packet)

def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback)

start_sniffing()

