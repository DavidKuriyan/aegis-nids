import os
import csv
from datetime import datetime
import config
import database

# Ensure the log folder exists
os.makedirs(config.LOG_DIR, exist_ok=True)

def initialize_csv():
    """
    Initializes the alerts CSV backup file by writing headers if the file doesn't exist.
    """
    if not os.path.exists(config.CSV_ALERT_PATH):
        try:
            with open(config.CSV_ALERT_PATH, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp", "Source IP", "Destination IP", 
                    "Source Port", "Destination Port", "Protocol", 
                    "Attack Type", "Risk Level", "Packet Count", "Flow Duration (s)"
                ])
            print(f"Alerts CSV log initialized at: {config.CSV_ALERT_PATH}")
        except Exception as e:
            print(f"Error initializing CSV log file: {e}")

def trigger_alert(src_ip, dst_ip, src_port, dst_port, protocol, attack_type, risk_level, packet_count, flow_duration):
    """
    Triggers an intrusion alert. Logs to console, SQLite database, and CSV backup file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Console Alert (Formatted, professional SOC style)
    border = "=" * 56
    print(f"\n[!] INTRUSION DETECTED AT {timestamp}")
    print(border)
    print(f"  ATTACK TYPE : {attack_type}")
    print(f"  RISK LEVEL  : {risk_level}")
    print(f"  SOURCE IP   : {src_ip}:{src_port}")
    print(f"  DEST IP     : {dst_ip}:{dst_port}")
    print(f"  PROTOCOL    : {protocol}")
    print(f"  DETAILS     : Flow Duration: {flow_duration:.4f}s | Packets in Flow: {packet_count}")
    print(border + "\n")
    
    # 2. Database Log
    try:
        database.insert_alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            attack_type=attack_type,
            risk_level=risk_level,
            packet_count=packet_count,
            flow_duration=flow_duration
        )
    except Exception as e:
        print(f"Failed to log alert to SQLite: {e}")
        
    # 3. CSV File Log
    try:
        # Check again to ensure headers are active
        initialize_csv()
        with open(config.CSV_ALERT_PATH, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, src_ip, dst_ip, 
                src_port, dst_port, protocol, 
                attack_type, risk_level, packet_count, f"{flow_duration:.4f}"
            ])
    except Exception as e:
        print(f"Failed to log alert to CSV file: {e}")

if __name__ == "__main__":
    print("Alerts module loaded.")
