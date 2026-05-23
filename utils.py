import socket
import psutil
import threading
from collections import Counter
from scapy.all import conf

class KibanaStatsTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.ip_addresses = Counter()
        self.dns_queries = Counter()
        self.http_servers = Counter()
        self.user_agents = Counter()
        self.content_types = Counter()
        self.event_types = Counter()
        self.recent_events = []  # List of dicts
        
    def reset(self):
        with self.lock:
            self.ip_addresses.clear()
            self.dns_queries.clear()
            self.http_servers.clear()
            self.user_agents.clear()
            self.content_types.clear()
            self.event_types.clear()
            self.recent_events.clear()
            
    def add_event_row(self, timestamp, action, src_ip, src_port, dst_ip, dst_port, content_type="", url="", indicator=""):
        """
        Appends a row to the recent_events log only.
        Counters (ip_addresses, event_types) are NOT updated here — they
        are updated directly in packet_capture to avoid double-counting.
        Only call this for notable protocol events (DNS, HTTP, ICMP).
        """
        with self.lock:
            self.recent_events.insert(0, {
                "time": timestamp,
                "action": action,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "content_type": content_type,
                "url": url,
                "indicator": indicator
            })
            if len(self.recent_events) > 100:
                self.recent_events = self.recent_events[:100]

    def add_packet(self, timestamp, action, src_ip, src_port, dst_ip, dst_port, content_type="", url="", indicator=""):
        """Legacy helper — updates counters AND adds a row. 
        Prefer using direct counter updates + add_event_row() for notable events only."""
        with self.lock:
            self.event_types[action] += 1
            if src_ip: self.ip_addresses[src_ip] += 1
            if dst_ip: self.ip_addresses[dst_ip] += 1
            self.recent_events.insert(0, {
                "time": timestamp,
                "action": action,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "content_type": content_type,
                "url": url,
                "indicator": indicator
            })
            if len(self.recent_events) > 100:
                self.recent_events = self.recent_events[:100]

                
    def mark_indicator(self, src_ip, dst_ip, src_port, dst_port, protocol, attack_type):
        with self.lock:
            for ev in self.recent_events:
                if (ev["src_ip"] == src_ip and ev["dst_ip"] == dst_ip and 
                    ev["src_port"] == src_port and ev["dst_port"] == dst_port):
                    ev["indicator"] = attack_type
                    
    def get_stats(self):
        with self.lock:
            return {
                "ip_addresses": dict(self.ip_addresses.most_common(10)),
                "dns_queries": dict(self.dns_queries.most_common(10)),
                "http_servers": dict(self.http_servers.most_common(10)),
                "user_agents": dict(self.user_agents.most_common(5)),
                "content_types": dict(self.content_types.most_common(5)),
                "event_types": dict(self.event_types),
                "recent_events": list(self.recent_events)
            }

kibana_tracker = KibanaStatsTracker()

def find_loopback_interface():
    """
    Scans Scapy interfaces to locate the loopback adapter name.
    """
    for dev_name, iface_obj in conf.ifaces.items():
        name = getattr(iface_obj, "name", dev_name)
        description = getattr(iface_obj, "description", "").lower()
        if "loopback" in description or "loopback" in name.lower() or name == "lo0" or name == "lo":
            return name
    return None

def get_protocol_name(proto_num):
    """
    Translates transport layer protocol numbers into readable text names.
    """
    protocol_map = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
        2: "IGMP"
    }
    return protocol_map.get(proto_num, f"Proto-{proto_num}")

def list_network_interfaces():
    """
    Scans and returns available network interfaces mapped to their names, description,
    IP addresses, and Scapy-compatible GUID identifiers.
    Optimized for Windows environment.
    """
    interfaces = {}
    
    # Get active IPs for interfaces from psutil
    ip_map = {}
    try:
        for iface_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_map[iface_name] = addr.address
    except Exception as e:
        print(f"Warning: Could not fetch interface IPs via psutil: {e}")

    # Gather interface metadata from Scapy config
    index = 0
    for dev_name, iface_obj in sorted(conf.ifaces.items(), key=lambda x: str(x[0])):
        # Scapy on Windows uses GUIDs or indices
        description = getattr(iface_obj, "description", "Unknown Adapter")
        ip = getattr(iface_obj, "ip", "No IP")
        name = getattr(iface_obj, "name", dev_name)
        guid = getattr(iface_obj, "guid", dev_name)
        
        # Cross reference names with psutil names to resolve friendly name
        friendly_name = name
        for ps_name, ps_ip in ip_map.items():
            if ps_ip == ip:
                friendly_name = ps_name
                break
                
        # We only care about active physical interfaces or loopbacks
        if ip and ip != "0.0.0.0":
            interfaces[index] = {
                "scapy_name": name,
                "friendly_name": friendly_name,
                "description": description,
                "ip": ip,
                "guid": guid
            }
            index += 1
            
    return interfaces

if __name__ == "__main__":
    print("Available interfaces for packet capture:")
    ifaces = list_network_interfaces()
    for idx, info in ifaces.items():
        print(f"[{idx}] {info['friendly_name']} ({info['description']})")
        print(f"    IP: {info['ip']}")
        print(f"    Scapy Name: {info['scapy_name']}")
        print("-" * 50)
