import threading
import queue
import os
import psutil
from flask import Flask, render_template, jsonify, request
import config
import database
import alerts
import utils
from utils import kibana_tracker, find_loopback_interface
import train_model
from packet_capture import PacketCaptureEngine
from predict import PredictionEngine

# Initialize Flask App
app = Flask(__name__, template_folder="templates", static_folder="static")

# Thread and Engine Managers (Global States)
prediction_queue = queue.Queue()
capture_engine = None
loopback_engine = None
predict_engine = None
selected_interface_idx = -1

# Retraining states
is_training = False
training_status_msg = "Model ready"
training_error_occurred = False

# Lock to protect thread spin-ups/spin-downs
engine_lock = threading.Lock()

def start_engines(interface_name=None):
    """
    Spins up both the Packet Capture Engine and the Prediction Engine in separate threads.
    Also starts a parallel loopback sniffer if a separate loopback adapter is found.
    """
    global capture_engine, predict_engine, loopback_engine, prediction_queue
    
    with engine_lock:
        # 1. Start Prediction Engine first (so it's ready to handle queue items)
        if predict_engine is None or not predict_engine.is_alive():
            # Clear any stale queue items
            while not prediction_queue.empty():
                try:
                    prediction_queue.get_nowait()
                except queue.Empty:
                    break
            
            predict_engine = PredictionEngine(prediction_queue)
            predict_engine.daemon = True
            predict_engine.start()
            
        # 2. Start primary Packet Capture Engine
        if capture_engine is None or not capture_engine.is_alive():
            capture_engine = PacketCaptureEngine(interface_name, prediction_queue)
            capture_engine.daemon = True
            capture_engine.start()
            predict_engine.capture_engine = capture_engine
            
        # 3. Start secondary loopback capture engine (if different from primary)
        loopback_iface = find_loopback_interface()
        if loopback_iface:
            is_same = False
            if interface_name:
                is_same = (loopback_iface.lower().strip() == interface_name.lower().strip())
            if not is_same:
                if loopback_engine is None or not loopback_engine.is_alive():
                    loopback_engine = PacketCaptureEngine(loopback_iface, prediction_queue)
                    loopback_engine.daemon = True
                    loopback_engine.start()
                    print(f"[*] Parallel loopback sniffer started on: {loopback_iface}")
            
        print(f"[*] Core engines successfully started on adapter: {interface_name or 'Default'}")

def stop_engines():
    """
    Gracefully stops both packet capture and prediction engine threads.
    """
    global capture_engine, predict_engine, loopback_engine
    
    with engine_lock:
        if loopback_engine is not None:
            loopback_engine.stop()
            loopback_engine.join(timeout=3.0)
            loopback_engine = None
            
        if capture_engine is not None:
            capture_engine.stop()
            capture_engine.join(timeout=3.0)
            capture_engine = None
            
        if predict_engine is not None:
            predict_engine.stop()
            predict_engine.join(timeout=3.0)
            predict_engine = None
            
        print("[*] Core engines successfully stopped.")

# ========================================================
# FLASK HTTP ROUTES & ENDPOINTS
# ========================================================

@app.route("/")
def index():
    """
    Renders the main dashboard page.
    """
    return render_template("index.html")

@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """
    Lists all available active IPv4 interfaces on Windows.
    """
    try:
        ifaces = utils.list_network_interfaces()
        return jsonify({"status": "success", "interfaces": ifaces})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/start", methods=["POST"])
def start_ids():
    """
    Endpoint to start network sniffing on a specific interface index.
    """
    global selected_interface_idx
    data = request.json or {}
    iface_idx = data.get("interface_idx", -1)
    
    ifaces = utils.list_network_interfaces()
    if iface_idx not in ifaces and iface_idx != -1:
        return jsonify({"status": "error", "message": "Invalid interface index selected."}), 400
        
    try:
        selected_interface_idx = iface_idx
        iface_name = ifaces[iface_idx]["scapy_name"] if iface_idx in ifaces else None
        
        start_engines(iface_name)
        return jsonify({
            "status": "success", 
            "message": f"IDS started successfully.",
            "interface": ifaces.get(iface_idx, {"friendly_name": "Default / All"})["friendly_name"]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/stop", methods=["POST"])
def stop_ids():
    """
    Endpoint to stop network sniffing.
    """
    global selected_interface_idx
    try:
        stop_engines()
        selected_interface_idx = -1
        return jsonify({"status": "success", "message": "IDS stopped successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/status", methods=["GET"])
def get_status():
    """
    Fetches real-time status of engines, system resource consumption, and current sniffing adapter.
    """
    is_sniffing = capture_engine is not None and capture_engine.is_alive()
    is_predicting = predict_engine is not None and predict_engine.is_alive()
    
    # Resolve adapter description
    active_adapter = "None"
    if is_sniffing and selected_interface_idx != -1:
        ifaces = utils.list_network_interfaces()
        if selected_interface_idx in ifaces:
            active_adapter = ifaces[selected_interface_idx]["friendly_name"]
            
    # System Stats
    cpu_percent = psutil.cpu_percent()
    ram = psutil.virtual_memory()
    ram_percent = ram.percent
    
    # Capture Traffic Stats - aggregate from both engines
    capture_stats = {
        "total_packets": 0,
        "total_bytes": 0,
        "benign_packets": 0,
        "malicious_packets": 0,
        "active_flows": 0
    }
    if capture_engine:
        cs = capture_engine.get_stats()
        for k in capture_stats:
            capture_stats[k] += cs.get(k, 0)
    if loopback_engine:
        ls = loopback_engine.get_stats()
        for k in capture_stats:
            capture_stats[k] += ls.get(k, 0)
        
    # Model Availability Checks
    model_trained = (os.path.exists(config.MODEL_PATH) and 
                     os.path.exists(config.SCALER_PATH) and 
                     os.path.exists(config.LABEL_ENCODER_PATH))
    
    return jsonify({
        "status": "success",
        "engines": {
            "packet_capture": "RUNNING" if is_sniffing else "STOPPED",
            "prediction_engine": "RUNNING" if is_predicting else "STOPPED",
            "model_status": "TRAINED" if model_trained else "NOT TRAINED"
        },
        "active_adapter": active_adapter,
        "system_resources": {
            "cpu": cpu_percent,
            "ram": ram_percent
        },
        "traffic_stats": capture_stats,
        "kibana_stats": kibana_tracker.get_stats(),
        "training_state": {
            "is_training": is_training,
            "status_msg": training_status_msg,
            "error": training_error_occurred
        }
    })

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    Queries SQLite and returns the 50 most recent detected threat alerts.
    """
    limit = request.args.get("limit", 50, type=int)
    alerts_list = database.get_recent_alerts(limit)
    return jsonify({"status": "success", "alerts": alerts_list})

@app.route("/api/charts/stats", methods=["GET"])
def get_chart_stats():
    """
    Returns aggregated security metrics (attacks by type, threat levels).
    """
    stats = database.get_alert_stats()
    return jsonify({"status": "success", "stats": stats})

@app.route("/api/charts/history", methods=["GET"])
def get_traffic_history():
    """
    Returns the time-series packet rates for flow plotting.
    """
    limit = request.args.get("limit", 20, type=int)
    history = database.get_traffic_history(limit)
    return jsonify({"status": "success", "history": history})

def inject_mock_attack(attack_type):
    """
    Directly places mock flow features onto the prediction queue.
    This bypasses Scapy sniffing and is 100% safe (does not send network packets).
    """
    global prediction_queue
    
    if attack_type == "port_scan":
        # Inject 15 flows targeting unique ports to trigger stateful alarm (needs >= 5 unique ports)
        src_ip = "192.168.1.180"
        dst_ip = "192.168.1.10"
        for i in range(15):
            dst_port = 1000 + i
            features = {
                "Destination Port": dst_port,
                "Protocol": 6,  # TCP
                "Flow Duration": 50,
                "Total Fwd Packets": 1,
                "Total Length of Fwd Packets": 40,
                "Fwd Packet Length Max": 40,
                "Fwd Packet Length Min": 40,
                "Fwd Packet Length Mean": 40.0,
                "Flow Bytes/s": 800000.0,
                "Flow Packets/s": 20000.0,
                "SYN Flag Count": 1,
                "RST Flag Count": 0,
                "PSH Flag Count": 0,
                "ACK Flag Count": 0
            }
            flow_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": 54321 + i,
                "dst_port": dst_port,
                "protocol": 6,
                "packet_count": 1,
                "duration": 0.00005
            }
            prediction_queue.put({"features": features, "flow_info": flow_info})
            
    elif attack_type == "ddos":
        # DDoS UDP Flood: high packet count flow matching training set profile
        src_ip = "185.220.101.5"
        dst_ip = "192.168.1.10"
        features = {
            "Destination Port": 80,
            "Protocol": 17,  # UDP
            "Flow Duration": 150.0,
            "Total Fwd Packets": 120,
            "Total Length of Fwd Packets": 61440,
            "Fwd Packet Length Max": 512,
            "Fwd Packet Length Min": 512,
            "Fwd Packet Length Mean": 512.0,
            "Flow Bytes/s": 409600000.0,
            "Flow Packets/s": 800000.0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0
        }
        flow_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 55555,
            "dst_port": 80,
            "protocol": 17,
            "packet_count": 120,
            "duration": 0.00015
        }
        prediction_queue.put({"features": features, "flow_info": flow_info})
        
    elif attack_type == "ftp_brute":
        # FTP brute force simulation matching training set profile
        src_ip = "172.16.2.45"
        dst_ip = "192.168.1.10"
        features = {
            "Destination Port": 21,
            "Protocol": 6,  # TCP
            "Flow Duration": 3500.0,
            "Total Fwd Packets": 8,
            "Total Length of Fwd Packets": 640,
            "Fwd Packet Length Max": 120,
            "Fwd Packet Length Min": 40,
            "Fwd Packet Length Mean": 80.0,
            "Flow Bytes/s": 182857.1,
            "Flow Packets/s": 2285.7,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 1,
            "ACK Flag Count": 1
        }
        flow_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 49150,
            "dst_port": 21,
            "protocol": 6,
            "packet_count": 8,
            "duration": 0.0035
        }
        prediction_queue.put({"features": features, "flow_info": flow_info})
        
    elif attack_type == "ssh_brute":
        # SSH brute force simulation matching training set profile
        src_ip = "172.16.2.46"
        dst_ip = "192.168.1.10"
        features = {
            "Destination Port": 22,
            "Protocol": 6,  # TCP
            "Flow Duration": 5500.0,
            "Total Fwd Packets": 12,
            "Total Length of Fwd Packets": 1200,
            "Fwd Packet Length Max": 150,
            "Fwd Packet Length Min": 50,
            "Fwd Packet Length Mean": 100.0,
            "Flow Bytes/s": 218181.8,
            "Flow Packets/s": 2181.8,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 1,
            "ACK Flag Count": 1
        }
        flow_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 50220,
            "dst_port": 22,
            "protocol": 6,
            "packet_count": 12,
            "duration": 0.0055
        }
        prediction_queue.put({"features": features, "flow_info": flow_info})

def run_raw_packet_simulation(attack_type):
    """
    Launches a background thread to generate actual network packets targeting localhost loopback.
    """
    try:
        import simulate_attacks
    except ImportError:
        return False
        
    target_ip = "127.0.0.1"
    loopback_iface = find_loopback_interface()
    
    def worker():
        try:
            if attack_type == "port_scan":
                simulate_attacks.simulate_port_scan(target_ip, loopback_iface)
            elif attack_type == "ddos":
                simulate_attacks.simulate_ddos(target_ip, loopback_iface)
            elif attack_type == "ftp_brute":
                simulate_attacks.simulate_ftp_brute_force(target_ip, loopback_iface)
            elif attack_type == "ssh_brute":
                simulate_attacks.simulate_ssh_brute_force(target_ip, loopback_iface)
        except Exception as e:
            print(f"Error in background raw simulation: {e}")
            
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    return True

@app.route("/api/simulate", methods=["POST"])
def run_simulation():
    """
    Endpoint to simulate threat attacks.
    """
    data = request.json or {}
    attack_type = data.get("type")
    mode = data.get("mode", "inject")
    
    if attack_type not in ["port_scan", "ddos", "ftp_brute", "ssh_brute"]:
        return jsonify({"status": "error", "message": "Invalid attack type selected."}), 400
        
    try:
        if mode == "inject":
            inject_mock_attack(attack_type)
            return jsonify({"status": "success", "message": f"Successfully injected {attack_type} attack mock flows."})
        else:
            success = run_raw_packet_simulation(attack_type)
            if success:
                return jsonify({"status": "success", "message": f"Successfully launched raw {attack_type} simulation in background."})
            else:
                return jsonify({"status": "error", "message": "Failed to launch raw packet simulation. Ensure Scapy dependencies are met."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/retrain", methods=["POST"])
def retrain_model_endpoint():
    """
    Spins up a background thread to generate the dataset and retrain the Random Forest model.
    """
    global is_training, training_status_msg, training_error_occurred
    
    if is_training:
        return jsonify({"status": "error", "message": "Training is already in progress."}), 400
        
    def worker():
        global is_training, training_status_msg, training_error_occurred
        is_training = True
        training_error_occurred = False
        training_status_msg = "Preparing dataset..."
        
        try:
            # 1. Generate dataset if not existing
            if not os.path.exists(config.DATASET_PATH):
                from dataset.simulate_dataset import generate_mock_dataset
                generate_mock_dataset()
            
            # 2. Train model
            training_status_msg = "Training Random Forest Classifier..."
            success = train_model.train_ids_model()
            
            if success:
                training_status_msg = "Model trained successfully!"
            else:
                training_status_msg = "Training failed. Check logs."
                training_error_occurred = True
        except Exception as e:
            training_status_msg = f"Training exception: {str(e)}"
            training_error_occurred = True
        finally:
            is_training = False
            
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "success", "message": "Model retraining started."})

@app.route("/api/clear", methods=["POST"])
def clear_db_logs():
    """
    Clears all logs and alerts in the database and backup CSV files.
    """
    try:
        # Clear SQLite Tables
        database.clear_logs()
        
        # Reset CSV File
        if os.path.exists(config.CSV_ALERT_PATH):
            os.remove(config.CSV_ALERT_PATH)
        alerts.initialize_csv()
        
        # Reset kibana tracker
        kibana_tracker.reset()
        
        # Reset Capture Engine counts if running
        global capture_engine, loopback_engine
        if capture_engine:
            capture_engine.total_packets_captured = 0
            capture_engine.total_bytes_captured = 0
            capture_engine.benign_packets_count = 0
            capture_engine.malicious_packets_count = 0
        if loopback_engine:
            loopback_engine.total_packets_captured = 0
            loopback_engine.total_bytes_captured = 0
            loopback_engine.benign_packets_count = 0
            loopback_engine.malicious_packets_count = 0
            
        return jsonify({"status": "success", "message": "Logs and alerts cleared."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ========================================================
# INITIALIZATION & ENTRY
# ========================================================

def main():
    """
    Sets up resources and starts the Flask web server.
    """
    # 1. Initialize SQLite Database
    print("[*] Initializing SQLite database schema...")
    database.init_database()
    
    # 3. Print environment info
    print("\n" + "=" * 50)
    print("  AI-POWERED REAL-TIME NIDS RUNNING")
    print(f"  Access the dashboard: http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print("=" * 50 + "\n")
    
    # 4. Start Flask Server
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.DEBUG_MODE, use_reloader=False)

if __name__ == "__main__":
    main()
