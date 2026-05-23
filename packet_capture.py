import threading
import queue
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.dns import DNS
import config
from feature_extraction import FlowTracker
import utils

class PacketCaptureEngine(threading.Thread):
    """
    Background worker thread that sniffs live network packets using Scapy,
    extracts flow features, and places features onto the prediction queue.
    """
    def __init__(self, interface_name=None, prediction_queue=None):
        super().__init__()
        self.interface_name = interface_name
        self.prediction_queue = prediction_queue if prediction_queue is not None else queue.Queue()
        self.flow_tracker = FlowTracker()
        
        # Threat engine control states
        self.running = False
        self.stop_event = threading.Event()
        
        # Real-time traffic statistics (for dashboard KPIs)
        self.total_packets_captured = 0
        self.total_bytes_captured = 0
        self.benign_packets_count = 0
        self.malicious_packets_count = 0
        
        # Flow cleanup configuration
        self.last_cleanup_time = time.time()
        
    def run(self):
        """
        Thread execution entry point.
        """
        self.running = True
        print(f"[*] Starting Packet Capture Engine on interface: {self.interface_name or 'Default'}")
        
        # Build filter (capture only IPv4 TCP, UDP, and ICMP to reduce processing overhead)
        bpf_filter = "ip and (tcp or udp or icmp)"
        
        try:
            sniff(
                iface=self.interface_name,
                prn=self.packet_callback,
                filter=bpf_filter,
                stop_filter=self.should_stop_sniffing,
                store=0  # Do not store packets in memory (prevents leaks)
            )
        except Exception as e:
            print(f"[!] Error in packet sniffing thread: {e}")
        finally:
            self.running = False
            print("[*] Packet Capture Engine stopped.")
 
    def stop(self):
        """
        Signals the sniffing thread to terminate.
        """
        self.stop_event.set()
        
    def should_stop_sniffing(self, packet):
        """
        Scapy stop filter callback. Stops sniffing when stop_event is set.
        """
        return self.stop_event.is_set()
 
    def packet_callback(self, packet):
        """
        Processes each sniffed packet:
        1. Decodes layers (IP, TCP/UDP)
        2. Resolves IPs, Ports, Protocol
        3. Updates flow trackers
        4. Submits flow details to queue for prediction
        """
        # Increment raw counters
        self.total_packets_captured += 1
        pkt_len = len(packet)
        self.total_bytes_captured += pkt_len
        
        # Check for IP layer (IPv4)
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        src_port = 0
        dst_port = 0
        tcp_flags = {}
        
        action = "ip"
        content_type = ""
        url = ""
        
        # Extract Transport Layer Metadata
        if protocol == 6 and packet.haslayer(TCP):  # TCP
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            action = "tcp_connection"
            
            # Extract TCP Flags (FIN, SYN, RST, PSH, ACK, URG)
            flags_str = str(tcp_layer.flags)
            tcp_flags = {
                'SYN': 'S' in flags_str,
                'RST': 'R' in flags_str,
                'PSH': 'P' in flags_str,
                'ACK': 'A' in flags_str
            }
            
            # Parse HTTP metadata
            payload = bytes(tcp_layer.payload)
            if payload:
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if "GET " in payload_str or "POST " in payload_str:
                        action = "http_request"
                        host_header = ""
                        for line in payload_str.split("\r\n"):
                            if line.lower().startswith("host:"):
                                host_header = line.split(":", 1)[1].strip()
                            if line.lower().startswith("user-agent:"):
                                ua = line.split(":", 1)[1].strip()
                                utils.kibana_tracker.user_agents[ua] += 1
                        
                        req_line = payload_str.split("\r\n")[0]
                        url = req_line.split(" ")[1] if len(req_line.split(" ")) > 1 else ""
                        if host_header:
                            url = f"http://{host_header}{url}"
                            utils.kibana_tracker.http_servers[host_header] += 1
                            
                    elif "HTTP/1." in payload_str:
                        action = "http_response"
                        for line in payload_str.split("\r\n"):
                            if line.lower().startswith("content-type:"):
                                ct = line.split(":", 1)[1].strip().split(";")[0]
                                content_type = ct
                                utils.kibana_tracker.content_types[ct] += 1
                except Exception:
                    pass
                    
        elif protocol == 17 and packet.haslayer(UDP):  # UDP
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            action = "udp_message"
            
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                action = "dns_message"
                if dns_layer.qr == 0 and dns_layer.qd:
                    try:
                        qname = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                        utils.kibana_tracker.dns_queries[qname] += 1
                    except Exception:
                        pass
        elif protocol == 1:
            action = "icmp"
            
        # --- Kibana Tracker Update ---
        # Always count IP addresses and event types (for charts), but
        # only add to recent_events for NOTABLE traffic (DNS, HTTP, ICMP).
        # This prevents plain background TCP connections flooding the raw events table.
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Count IPs and event types for ALL packets
        with utils.kibana_tracker.lock:
            utils.kibana_tracker.ip_addresses[src_ip] += 1
            utils.kibana_tracker.ip_addresses[dst_ip] += 1
            utils.kibana_tracker.event_types[action] += 1
        
        # Only add a row to recent_events for notable protocols
        if action in ("dns_message", "http_request", "http_response", "icmp"):
            utils.kibana_tracker.add_event_row(
                timestamp=timestamp_str,
                action=action,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                content_type=content_type,
                url=url,
                indicator=""
            )
        
        # Update flow stats
        flow, direction = self.flow_tracker.process_packet(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=pkt_len,
            tcp_flags=tcp_flags
        )
        
        # Extract features for prediction
        features = flow.extract_features()
        
        # Package prediction context
        predict_item = {
            "features": features,
            "engine": self,
            "flow_info": {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "packet_count": flow.tot_fwd_pkts + flow.tot_bwd_pkts,
                "duration": flow.get_duration_microseconds() / 1e6
            }
        }
        
        # Queue the item for prediction
        self.prediction_queue.put(predict_item)
        
        # Periodic inactive flow purger
        current_time = time.time()
        if current_time - self.last_cleanup_time > config.FLOW_CLEANUP_INTERVAL:
            cleaned = self.flow_tracker.cleanup_expired_flows()
            if cleaned > 0:
                # Debug message optional, keep commented for performance
                # print(f"[*] Cleared {cleaned} expired idle flows from memory.")
                pass
            self.last_cleanup_time = current_time
            
    def get_stats(self):
        """
        Returns snapshot of live traffic stats.
        """
        return {
            "total_packets": self.total_packets_captured,
            "total_bytes": self.total_bytes_captured,
            "benign_packets": self.benign_packets_count,
            "malicious_packets": self.malicious_packets_count,
            "active_flows": len(self.flow_tracker.flows)
        }
