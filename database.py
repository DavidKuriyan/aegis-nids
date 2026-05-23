import sqlite3
import os
from datetime import datetime
import config

def get_db_connection():
    """
    Creates and returns a thread-safe connection to the SQLite database.
    Ensures the parent directory exists.
    """
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_database():
    """
    Initializes the database schema by creating alerts and traffic_stats tables.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            attack_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            packet_count INTEGER,
            flow_duration REAL
        )
    """)
    
    # Create Traffic Stats Table (10-second aggregation windows for live charting)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            window_time TEXT PRIMARY KEY,
            total_packets INTEGER DEFAULT 0,
            benign_packets INTEGER DEFAULT 0,
            malicious_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0
        )
    """)
    
    conn.commit()
    conn.close()
    print(f"SQLite database initialized at: {config.DATABASE_PATH}")

def insert_alert(src_ip, dst_ip, src_port, dst_port, protocol, attack_type, risk_level, packet_count, flow_duration):
    """
    Inserts a detected attack alert into the alerts table.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        cursor.execute("""
            INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, risk_level, packet_count, flow_duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, risk_level, packet_count, flow_duration))
        conn.commit()
    except Exception as e:
        print(f"Error inserting alert to database: {e}")
    finally:
        conn.close()

def log_traffic_window(total_pkts, benign_pkts, malicious_pkts, total_bytes):
    """
    Aggregates traffic details into 10-second windows in the traffic_stats table.
    Uses UPSERT to increment counts for the current window.
    """
    # Round current time to nearest 10 seconds for window binning
    now = datetime.now()
    second_rounded = (now.second // 10) * 10
    window_time = now.replace(second=second_rounded, microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO traffic_stats (window_time, total_packets, benign_packets, malicious_packets, total_bytes)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(window_time) DO UPDATE SET
                total_packets = total_packets + excluded.total_packets,
                benign_packets = benign_packets + excluded.benign_packets,
                malicious_packets = malicious_packets + excluded.malicious_packets,
                total_bytes = total_bytes + excluded.total_bytes
        """, (window_time, total_pkts, benign_pkts, malicious_pkts, total_bytes))
        conn.commit()
    except Exception as e:
        print(f"Error logging traffic window: {e}")
    finally:
        conn.close()

def get_recent_alerts(limit=50):
    """
    Fetches the most recent alerts from the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        alerts = [dict(row) for row in cursor.fetchall()]
        return alerts
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return []
    finally:
        conn.close()

def get_alert_stats():
    """
    Returns aggregated stats for dashboard visual metrics:
    - Attack types breakdown
    - Risk level breakdown
    - Total alert count
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    stats = {}
    
    try:
        # Attack types
        cursor.execute("SELECT attack_type, COUNT(*) as count FROM alerts GROUP BY attack_type")
        stats["attack_types"] = {row["attack_type"]: row["count"] for row in cursor.fetchall()}
        
        # Risk levels
        cursor.execute("SELECT risk_level, COUNT(*) as count FROM alerts GROUP BY risk_level")
        stats["risk_levels"] = {row["risk_level"]: row["count"] for row in cursor.fetchall()}
        
        # Total alerts
        cursor.execute("SELECT COUNT(*) as count FROM alerts")
        stats["total_alerts"] = cursor.fetchone()["count"]
        
    except Exception as e:
        print(f"Error fetching alert stats: {e}")
        stats = {"attack_types": {}, "risk_levels": {}, "total_alerts": 0}
    finally:
        conn.close()
        
    return stats

def get_traffic_history(limit=30):
    """
    Fetches the history of 10-second traffic windows for time-series charts.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT window_time, total_packets, benign_packets, malicious_packets, total_bytes 
            FROM traffic_stats 
            ORDER BY window_time DESC LIMIT ?
        """, (limit,))
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except Exception as e:
        print(f"Error fetching traffic history: {e}")
        return []
    finally:
        conn.close()

def clear_logs():
    """
    Clears all alerts and traffic statistics tables.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM traffic_stats")
        conn.commit()
        print("Database logs cleared successfully.")
    except Exception as e:
        print(f"Error clearing logs: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Test DB creation
    init_database()
    print("Database schema initialized.")
