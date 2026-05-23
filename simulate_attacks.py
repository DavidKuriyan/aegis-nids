import sys
import os
import time
from scapy.all import Ether, IP, TCP, UDP, sendp
import utils
from utils import find_loopback_interface

def print_banner():
    print("=" * 60)
    print("      Aegis NIDS - Attack Simulation Traffic Generator      ")
    print("      (Educational & Local Lab Testing Defensive Use Only)  ")
    print("=" * 60)

def get_target_ip():
    # We default to loopback or host local IP
    ip = input("Enter Target IP to send traffic to (default: 127.0.0.1): ").strip()
    return ip if ip else "127.0.0.1"

def send_pkt(pkt, iface):
    """
    Sends a Layer 2 packet via sendp if an interface is provided.
    Otherwise, strips Layer 2 and sends via Layer 3 send() fallback.
    """
    if iface:
        sendp(pkt, iface=iface, verbose=0)
    else:
        from scapy.all import send
        send(pkt[IP], verbose=0)

def simulate_port_scan(target_ip, iface=None):
    if iface is None:
        iface = find_loopback_interface()
    print(f"\n[*] Simulating Port Scan (SYN Sweep) to {target_ip} on interface {iface or 'Default'}...")
    print("[*] Sending TCP SYN packets to 50 sequential ports...")
    
    for port in range(1000, 1050):
        # Construct SYN packet with Ether layer
        pkt = Ether() / IP(dst=target_ip) / TCP(sport=54321, dport=port, flags="S")
        send_pkt(pkt, iface)
        time.sleep(0.02)  # Fast rate
        
    print("[+] Port Scan simulation packets sent!")

def simulate_ddos(target_ip, iface=None):
    if iface is None:
        iface = find_loopback_interface()
    print(f"\n[*] Simulating DDoS flood attack to {target_ip} on interface {iface or 'Default'}...")
    print("[*] Flooding target with 1000 high-frequency UDP packets...")
    
    # Large volume, quick duration
    for i in range(1000):
        pkt = Ether() / IP(dst=target_ip) / UDP(sport=55555, dport=80) / ("X" * 500) # 500 bytes payload
        send_pkt(pkt, iface)
        if i % 100 == 0:
            print(f"    Sent {i}/1000 packets...")
            
    print("[+] DDoS simulation packets sent!")

def simulate_ftp_brute_force(target_ip, iface=None):
    if iface is None:
        iface = find_loopback_interface()
    print(f"\n[*] Simulating FTP Brute Force (Port 21) to {target_ip} on interface {iface or 'Default'}...")
    print("[*] Sending rapid authentication packets...")
    
    # Simulates multiple connection/auth sequences
    for i in range(25):
        # We send small TCP push/ack data representing auth requests
        pkt = Ether() / IP(dst=target_ip) / TCP(sport=49000 + i, dport=21, flags="PA") / "USER admin\r\n"
        send_pkt(pkt, iface)
        pkt = Ether() / IP(dst=target_ip) / TCP(sport=49000 + i, dport=21, flags="PA") / "PASS pass123\r\n"
        send_pkt(pkt, iface)
        time.sleep(0.1)
        
    print("[+] FTP Brute Force simulation packets sent!")

def simulate_ssh_brute_force(target_ip, iface=None):
    if iface is None:
        iface = find_loopback_interface()
    print(f"\n[*] Simulating SSH Brute Force (Port 22) to {target_ip} on interface {iface or 'Default'}...")
    print("[*] Sending rapid authentication connection attempts...")
    
    for i in range(20):
        # We send TCP handshake packets to port 22
        pkt = Ether() / IP(dst=target_ip) / TCP(sport=50000 + i, dport=22, flags="S")
        send_pkt(pkt, iface)
        time.sleep(0.05)
        
    print("[+] SSH Brute Force simulation packets sent!")

def main():
    if os.name != 'nt' and os.geteuid() != 0:
        print("[!] Warning: This script must be run with Administrator/Root privileges to send raw packets.")
        sys.exit(1)
        
    print_banner()
    
    # List active adapters to remind user
    print("\nDetecting active interfaces...")
    ifaces = utils.list_network_interfaces()
    for idx, info in ifaces.items():
        print(f"[{idx}] {info['friendly_name']} - IP: {info['ip']}")
    
    target_ip = get_target_ip()
    
    # Find loopback interface
    loopback_iface = find_loopback_interface()
    print(f"\n[*] Detected Loopback Interface: {loopback_iface}")
    
    while True:
        print("\nSelect Attack Vector to Simulate:")
        print("1. Port Scan (TCP SYN Sweep)")
        print("2. DDoS Flood (UDP Flood)")
        print("3. FTP Brute Force (Port 21)")
        print("4. SSH Brute Force (Port 22)")
        print("5. Run All Simulations")
        print("6. Exit")
        
        choice = input("Enter choice (1-6): ").strip()
        
        if choice == '1':
            simulate_port_scan(target_ip, loopback_iface)
        elif choice == '2':
            simulate_ddos(target_ip, loopback_iface)
        elif choice == '3':
            simulate_ftp_brute_force(target_ip, loopback_iface)
        elif choice == '4':
            simulate_ssh_brute_force(target_ip, loopback_iface)
        elif choice == '5':
            simulate_port_scan(target_ip, loopback_iface)
            time.sleep(2)
            simulate_ddos(target_ip, loopback_iface)
            time.sleep(2)
            simulate_ftp_brute_force(target_ip, loopback_iface)
            time.sleep(2)
            simulate_ssh_brute_force(target_ip, loopback_iface)
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("[!] Invalid option. Choose 1-6.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting attack simulator.")
