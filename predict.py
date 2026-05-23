import threading
import queue
import time
import os
import joblib
import pandas as pd
import numpy as np
import config
import alerts
import database
import utils
from utils import kibana_tracker

class PredictionEngine(threading.Thread):
    """
    Background worker thread that pulls flow records from the packet capture queue,
    runs them through the ML model, classifies them, and dispatches alerts for threats.
    """
    def __init__(self, prediction_queue, capture_engine=None):
        super().__init__()
        self.prediction_queue = prediction_queue
        self.capture_engine = capture_engine
        self.running = False
        self.stop_event = threading.Event()
        
        # Load preprocessors and classifier
        self.rf_model = None
        self.scaler = None
        self.label_encoder = None
        
        # Aggregation memory for 10-second traffic logging
        self.last_db_log_time = time.time()
        self.aggregated_total_pkts = 0
        self.aggregated_benign_pkts = 0
        self.aggregated_malicious_pkts = 0
        self.aggregated_bytes = 0
        
        # Stateful threat tracking variables
        self.port_scan_tracker = {}
        self.port_scan_lock = threading.Lock()
        
        # Alert deduplication: suppress repeats within 15 seconds per flow key
        self.alert_dedup = {}  # {flow_key: last_alert_time}
        self.dedup_lock = threading.Lock()
        
    def load_ml_components(self):
        """
        Attempts to load model, scaler, and encoder files from disk.
        Returns True if successful, False otherwise.
        """
        if (os.path.exists(config.MODEL_PATH) and 
            os.path.exists(config.SCALER_PATH) and 
            os.path.exists(config.LABEL_ENCODER_PATH)):
            try:
                self.rf_model = joblib.load(config.MODEL_PATH)
                self.scaler = joblib.load(config.SCALER_PATH)
                self.label_encoder = joblib.load(config.LABEL_ENCODER_PATH)
                print("[*] Loaded ML Model, Scaler, and Label Encoder successfully.")
                # Log model parameters for transparency
                n_features = len(config.FEATURES)
                classes = list(self.label_encoder.classes_)
                print(f"    - Model type: {type(self.rf_model).__name__}")
                print(f"    - Features count: {n_features}")
                print(f"    - Classes: {classes}")
                return True
            except Exception as e:
                print(f"[!] Error loading ML model components: {e}")
                return False
        else:
            print("[!] ML model components not found. Intrusions will be evaluated using signature fallbacks until model is trained.")
            return False

    def run(self):
        """
        Thread execution entry point.
        """
        self.running = True
        print("[*] Starting Prediction Engine...")
        
        # Initial load attempt
        loaded = self.load_ml_components()
        
        while not self.stop_event.is_set():
            try:
                # Retrieve items from queue (with a short timeout to check stop_event periodically)
                try:
                    item = self.prediction_queue.get(timeout=1.0)
                except queue.Empty:
                    # Check if it's time to log aggregated traffic statistics (even when idle)
                    self.check_and_log_traffic()
                    continue
                
                # Model hot-reload check (if model was loaded later)
                if not loaded:
                    loaded = self.load_ml_components()
                
                features_dict = item["features"]
                flow_info = item["flow_info"]
                # Grab the capture engine from the queue item if provided
                engine_ref = item.get("engine", None)
                if engine_ref is not None:
                    self.capture_engine = engine_ref
                
                # Track in-memory stats
                self.aggregated_total_pkts += 1
                pkt_bytes = features_dict["Total Length of Fwd Packets"]  # Approximate bytes from flow
                self.aggregated_bytes += pkt_bytes
                
                # ============================================================
                # ICMP SIGNATURE RULE (before ML - ICMP not in training data)
                # ============================================================
                protocol_num = flow_info.get("protocol", 0)
                packet_count = flow_info.get("packet_count", 0)
                
                if protocol_num == 1:  # ICMP
                    if packet_count >= 30:
                        attack_type = "DDoS (ICMP Flood)"
                        risk_level = "CRITICAL"
                    else:
                        attack_type = "BENIGN"
                        risk_level = "LOW"
                    # Skip ML prediction for ICMP
                    self._process_classification(attack_type, risk_level, flow_info, features_dict)
                    self.prediction_queue.task_done()
                    self.check_and_log_traffic()
                    continue
                
                # Perform ML prediction
                attack_type = "BENIGN"
                risk_level = "LOW"
                
                if loaded:
                    # 1. Structure feature vector in the exact order expected by config.FEATURES
                    features_df = pd.DataFrame([features_dict])[config.FEATURES]
                    
                    # 2. Scale features and reconstruct DataFrame to preserve feature names
                    features_scaled = self.scaler.transform(features_df)
                    features_scaled_df = pd.DataFrame(features_scaled, columns=config.FEATURES)
                    
                    # 3. Predict class using named features
                    pred_class_idx = self.rf_model.predict(features_scaled_df)[0]
                    attack_type = self.label_encoder.inverse_transform([pred_class_idx])[0]
                    risk_level = config.THREAT_LEVELS.get(attack_type, "LOW")
                else:
                    # Signature fallback rules when model is missing
                    # A basic signature check ensures immediate responsiveness even before training
                    dst_port = features_dict["Destination Port"]
                    syn_count = features_dict["SYN Flag Count"]
                    ack_count = features_dict["ACK Flag Count"]
                    
                    if syn_count > 20 and ack_count == 0:
                        attack_type = "PortScan"
                        risk_level = "MEDIUM"
                    elif features_dict["Flow Packets/s"] > 500:
                        attack_type = "DDoS"
                        risk_level = "CRITICAL"
                    elif dst_port in [21, 22] and features_dict["Total Fwd Packets"] > 15:
                        attack_type = "FTP-Patator" if dst_port == 21 else "SSH-Patator"
                        risk_level = "HIGH"
                
                # Stateful verification to filter out false positive alerts
                if attack_type == "PortScan":
                    with self.port_scan_lock:
                        now = time.time()
                        src_ip = flow_info["src_ip"]
                        dst_port = flow_info["dst_port"]
                        
                        if src_ip not in self.port_scan_tracker:
                            self.port_scan_tracker[src_ip] = []
                            
                        # Log connection attempt
                        self.port_scan_tracker[src_ip].append((now, dst_port))
                        
                        # Purge logs older than 15 seconds
                        self.port_scan_tracker[src_ip] = [
                            entry for entry in self.port_scan_tracker[src_ip]
                            if now - entry[0] <= 15.0
                        ]
                        
                        # Check unique ports contacted
                        unique_ports = set(entry[1] for entry in self.port_scan_tracker[src_ip])
                        
                        # Suppress PortScan unless at least 5 unique ports are contacted in 15 seconds
                        if len(unique_ports) < 5:
                            attack_type = "BENIGN"
                            risk_level = "LOW"
                            
                elif attack_type == "DDoS":
                    # DDoS flood flow requires substantial packet count (e.g. >= 30 packets)
                    if flow_info["packet_count"] < 30:
                        attack_type = "BENIGN"
                        risk_level = "LOW"
                        
                elif attack_type in ["SSH-Patator", "FTP-Patator", "Web Attack", "Bot", "Infiltration"]:
                    # Brute force or session-based attacks require multiple packets
                    if flow_info["packet_count"] < 5:
                        attack_type = "BENIGN"
                        risk_level = "LOW"
                
                # Handle classification outcomes
                self._process_classification(attack_type, risk_level, flow_info, features_dict)
                
                self.prediction_queue.task_done()
                
                # Check and log aggregated traffic statistics
                self.check_and_log_traffic()
                
            except Exception as e:
                print(f"[!] Error in prediction thread: {e}")
                import traceback
                traceback.print_exc()
                
        self.running = False
        # Commit any final remaining aggregated data before exit
        self.log_traffic_to_db()
        print("[*] Prediction Engine stopped.")

    def _process_classification(self, attack_type, risk_level, flow_info, features_dict):
        """
        Handles the result of a classification: increments counters, deduplicates alerts,
        dispatches to the alert system, and marks events in the kibana tracker.
        """
        if attack_type != "BENIGN":
            self.aggregated_malicious_pkts += 1
            if self.capture_engine:
                self.capture_engine.malicious_packets_count += 1
            
            # Alert deduplication: only fire once per 15 seconds per flow key
            flow_key = (flow_info["src_ip"], flow_info["dst_ip"], flow_info["dst_port"])
            now = time.time()
            should_alert = False
            with self.dedup_lock:
                last_time = self.alert_dedup.get(flow_key, 0)
                if now - last_time >= 15.0:
                    self.alert_dedup[flow_key] = now
                    should_alert = True
                
            if should_alert:
                alerts.trigger_alert(
                    src_ip=flow_info["src_ip"],
                    dst_ip=flow_info["dst_ip"],
                    src_port=flow_info["src_port"],
                    dst_port=flow_info["dst_port"],
                    protocol=utils.get_protocol_name(flow_info["protocol"]),
                    attack_type=attack_type,
                    risk_level=risk_level,
                    packet_count=flow_info["packet_count"],
                    flow_duration=flow_info["duration"]
                )
                # Mark matching event rows in kibana tracker with threat indicator
                kibana_tracker.mark_indicator(
                    src_ip=flow_info["src_ip"],
                    dst_ip=flow_info["dst_ip"],
                    src_port=flow_info["src_port"],
                    dst_port=flow_info["dst_port"],
                    protocol=flow_info["protocol"],
                    attack_type=attack_type
                )
        else:
            self.aggregated_benign_pkts += 1
            if self.capture_engine:
                self.capture_engine.benign_packets_count += 1

    def stop(self):
        """
        Signals the thread to terminate.
        """
        self.stop_event.set()

    def check_and_log_traffic(self):
        """
        Checks if the 10-second aggregation window has passed, and logs to SQLite.
        """
        current_time = time.time()
        if current_time - self.last_db_log_time >= 10.0:
            self.log_traffic_to_db()
            self.last_db_log_time = current_time

    def log_traffic_to_db(self):
        """
        Inserts in-memory accumulated counts into the database and resets buffers.
        """
        if self.aggregated_total_pkts > 0:
            database.log_traffic_window(
                total_pkts=self.aggregated_total_pkts,
                benign_pkts=self.aggregated_benign_pkts,
                malicious_pkts=self.aggregated_malicious_pkts,
                total_bytes=int(self.aggregated_bytes)
            )
            # Reset memory aggregators
            self.aggregated_total_pkts = 0
            self.aggregated_benign_pkts = 0
            self.aggregated_malicious_pkts = 0
            self.aggregated_bytes = 0
