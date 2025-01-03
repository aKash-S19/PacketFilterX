import os
import time
import logging
from datetime import datetime, timedelta
from scapy.all import sniff, ARP, TCP, IP

# Logging setup
logging.basicConfig(
    filename="PacketFilterX_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Global variables
connection_count = {}
arp_cache = {}

# Terminal colors
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
WHITE = "\033[97m"

# Menu display
def display_menu():
    os.system("clear" if os.name != "nt" else "cls")
    print(f"""
{GREEN}PacketFilterX: Real-Time Packet Sniffer and Analyzer{RESET}
{WHITE}---------------------------------------------------
1. Start Monitoring
2. View Logs
3. Exit
{RESET}
""")

# Port scanning detection
def detect_port_scanning(packet):
    if TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if src_ip not in connection_count:
            connection_count[src_ip] = set()
        connection_count[src_ip].add(dst_port)
        if len(connection_count[src_ip]) > 100:  # Threshold for scanning
            log_and_alert(f"Port scanning detected from {src_ip}")
            return False  # Mark as bad packet
    return True  # Mark as good packet

# ARP spoofing detection
def detect_arp_spoofing(packet):
    if ARP in packet and packet[ARP].op == 2:  # ARP reply
        real_mac = arp_cache.get(packet[ARP].psrc, None)
        if real_mac and real_mac != packet[ARP].hwsrc:
            log_and_alert(
                f"ARP spoofing detected: {packet[ARP].psrc} has MAC conflict {real_mac} vs {packet[ARP].hwsrc}"
            )
            return False  # Mark as bad packet
        arp_cache[packet[ARP].psrc] = packet[ARP].hwsrc
    return True  # Mark as good packet

# Log and alert function
def log_and_alert(message):
    print(f"{RED}[ALERT] {message}{RESET}")
    logging.info(message)

# Packet callback function
def packet_callback(packet):
    try:
        is_good = True
        if TCP in packet or IP in packet:
            is_good &= detect_port_scanning(packet)
        if ARP in packet:
            is_good &= detect_arp_spoofing(packet)
       
        # Packet details
        if IP in packet:
            packet_info = f"Packet: {packet[IP].src} -> {packet[IP].dst}"
        elif ARP in packet:
            packet_info = f"ARP: {packet[ARP].hwsrc} -> {packet[ARP].psrc}"
        else:
            packet_info = "Unknown Packet"
       
        # Display packet status
        if is_good:
            print(f"{GREEN}[GOOD] {packet_info}{RESET}")
            logging.info(f"Good packet: {packet_info}")
        else:
            print(f"{RED}[BAD] {packet_info}{RESET}")
            logging.info(f"Bad packet: {packet_info}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Start packet sniffing
def start_sniffer(interface, duration):
    stop_time = datetime.now() + timedelta(seconds=duration)
    print(f"{GREEN}[*] Starting sniffer on interface: {interface} for {duration} seconds...{RESET}")
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            stop_filter=lambda p: datetime.now() >= stop_time
        )
        print(f"{GREEN}[*] Scanning completed successfully.{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Stopping sniffer...{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

# View logs
def view_logs():
    if os.path.exists("PacketFilterX_logs.txt"):
        print(f"\n{WHITE}[Logs from PacketFilterX]{RESET}")
        with open("PacketFilterX_logs.txt", "r") as log_file:
            print(log_file.read())
    else:
        print(f"{RED}[!] No logs found.{RESET}")
    input(f"{WHITE}[Press Enter to continue...]{RESET}")

# Main program
def main():
    while True:
        display_menu()
        choice = input(f"{WHITE}[?] Select an option: {RESET}")
        if choice == "1":
            interface = input(f"{WHITE}[?] Enter network interface (e.g., eth0): {RESET}")
            try:
                duration = int(input(f"{WHITE}[?] Enter duration for scanning (in seconds): {RESET}"))
                start_sniffer(interface, duration)
                print(f"{GREEN}[*] Scanning complete. Check logs for details.{RESET}")
            except ValueError:
                print(f"{RED}[!] Invalid duration. Please enter a number.{RESET}")
        elif choice == "2":
            view_logs()
        elif choice == "3":
            print(f"{GREEN}[*] Exiting PacketFilterX. Goodbye!{RESET}")
            break
        else:
            print(f"{RED}[!] Invalid option. Please try again.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()