import time
import numpy as np
import config

class NetworkFlow:
    """
    Represents a bidirectional network communication flow.
    Tracks statistics required for NIDS Machine Learning feature extraction.
    """
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Timestamp trackers (stored as seconds since epoch)
        self.start_time = time.time()
        self.last_active = self.start_time
        
        # Flow packet/byte counts
        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        self.tot_len_fwd_pkts = 0
        self.tot_len_bwd_pkts = 0
        
        # Packet length trackers
        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []
        
        # TCP Flag counts
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        
    def add_packet(self, packet_size, direction, tcp_flags=None):
        """
        Updates flow metrics upon receiving a new packet.
        direction: 'fwd' (sender -> receiver) or 'bwd' (receiver -> sender)
        tcp_flags: dictionary of boolean flag values (SYN, RST, PSH, ACK)
        """
        self.last_active = time.time()
        
        if direction == 'fwd':
            self.tot_fwd_pkts += 1
            self.tot_len_fwd_pkts += packet_size
            self.fwd_pkt_lens.append(packet_size)
        else:
            self.tot_bwd_pkts += 1
            self.tot_len_bwd_pkts += packet_size
            self.bwd_pkt_lens.append(packet_size)
            
        if tcp_flags:
            if tcp_flags.get('SYN', 0): self.syn_flag_count += 1
            if tcp_flags.get('RST', 0): self.rst_flag_count += 1
            if tcp_flags.get('PSH', 0): self.psh_flag_count += 1
            if tcp_flags.get('ACK', 0): self.ack_flag_count += 1

    def get_duration_microseconds(self):
        """
        Returns flow duration in microseconds (CICIDS2017 standard).
        """
        duration = (self.last_active - self.start_time) * 1e6
        return max(duration, 1.0)  # Avoid exact 0 duration

    def extract_features(self):
        """
        Extracts the 14-feature vector compatible with the ML Model configuration.
        """
        duration_us = self.get_duration_microseconds()
        duration_sec = duration_us / 1e6
        
        # Basic calculations
        fwd_lens = self.fwd_pkt_lens if self.fwd_pkt_lens else [0]
        
        fwd_pkt_len_max = max(fwd_lens)
        fwd_pkt_len_min = min(fwd_lens)
        fwd_pkt_len_mean = sum(fwd_lens) / len(fwd_lens)
        
        total_bytes = self.tot_len_fwd_pkts + self.tot_len_bwd_pkts
        total_packets = self.tot_fwd_pkts + self.tot_bwd_pkts
        
        flow_bytes_sec = total_bytes / duration_sec
        flow_pkts_sec = total_packets / duration_sec
        
        # Build features ordered exactly as defined in config.FEATURES
        # 1. Destination Port
        # 2. Protocol
        # 3. Flow Duration
        # 4. Total Fwd Packets
        # 5. Total Length of Fwd Packets
        # 6. Fwd Packet Length Max
        # 7. Fwd Packet Length Min
        # 8. Fwd Packet Length Mean
        # 9. Flow Bytes/s
        # 10. Flow Packets/s
        # 11. SYN Flag Count
        # 12. RST Flag Count
        # 13. PSH Flag Count
        # 14. ACK Flag Count
        
        feature_vector = {
            "Destination Port": self.dst_port,
            "Protocol": self.protocol,
            "Flow Duration": duration_us,
            "Total Fwd Packets": self.tot_fwd_pkts,
            "Total Length of Fwd Packets": self.tot_len_fwd_pkts,
            "Fwd Packet Length Max": fwd_pkt_len_max,
            "Fwd Packet Length Min": fwd_pkt_len_min,
            "Fwd Packet Length Mean": fwd_pkt_len_mean,
            "Flow Bytes/s": flow_bytes_sec,
            "Flow Packets/s": flow_pkts_sec,
            "SYN Flag Count": self.syn_flag_count,
            "RST Flag Count": self.rst_flag_count,
            "PSH Flag Count": self.psh_flag_count,
            "ACK Flag Count": self.ack_flag_count
        }
        
        return feature_vector


class FlowTracker:
    """
    Manages active network flows, updates them with new packets, and purges expired flows.
    """
    def __init__(self):
        # Maps (src_ip, src_port, dst_ip, dst_port, protocol) -> NetworkFlow
        self.flows = {}
        
    def get_flow_keys(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """
        Returns keys in (forward_key, backward_key) format.
        """
        fwd_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        bwd_key = (dst_ip, dst_port, src_ip, src_port, protocol)
        return fwd_key, bwd_key

    def process_packet(self, src_ip, src_port, dst_ip, dst_port, protocol, packet_size, tcp_flags=None):
        """
        Associates an incoming packet with an existing flow, or spins up a new flow.
        Returns the updated NetworkFlow object and its direction ('fwd' or 'bwd').
        """
        fwd_key, bwd_key = self.get_flow_keys(src_ip, src_port, dst_ip, dst_port, protocol)
        
        if fwd_key in self.flows:
            flow = self.flows[fwd_key]
            flow.add_packet(packet_size, direction='fwd', tcp_flags=tcp_flags)
            return flow, 'fwd'
        elif bwd_key in self.flows:
            flow = self.flows[bwd_key]
            # If packet matched bwd_key, the packet travels from current src_ip (which is flow's dst_ip)
            # to flow's src_ip. This represents the backward direction.
            flow.add_packet(packet_size, direction='bwd', tcp_flags=tcp_flags)
            return flow, 'bwd'
        else:
            # Create a brand new flow
            new_flow = NetworkFlow(src_ip, src_port, dst_ip, dst_port, protocol)
            new_flow.add_packet(packet_size, direction='fwd', tcp_flags=tcp_flags)
            self.flows[fwd_key] = new_flow
            return new_flow, 'fwd'

    def cleanup_expired_flows(self):
        """
        Scans active flows and removes those that have timed out based on config.FLOW_TIMEOUT.
        Returns the number of cleaned flows.
        """
        now = time.time()
        expired_keys = []
        
        for key, flow in self.flows.items():
            if now - flow.last_active > config.FLOW_TIMEOUT:
                expired_keys.append(key)
                
        for key in expired_keys:
            del self.flows[key]
            
        return len(expired_keys)
