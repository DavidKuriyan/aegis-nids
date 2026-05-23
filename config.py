import os

# Base Directory of the Project
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Model Paths
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.joblib")

# Dataset Paths
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
DATASET_PATH = os.path.join(DATASET_DIR, "dataset.csv")

# Logs and Captures
LOG_DIR = os.path.join(BASE_DIR, "logs")
CSV_ALERT_PATH = os.path.join(LOG_DIR, "alerts.csv")
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")

# Database Path
DATABASE_PATH = os.path.join(BASE_DIR, "logs", "ids_database.db")

# Network Capture Settings
DEFAULT_INTERFACE = None  # None will trigger dynamic selection in app.py / utils.py
FLOW_TIMEOUT = 30.0       # Timeout in seconds to declare a network flow inactive/expired
FLOW_CLEANUP_INTERVAL = 10.0 # Time interval in seconds to purge expired flows from memory

# Web Dashboard Settings
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
DEBUG_MODE = False

# Ensure necessary directories exist
for directory in [MODEL_DIR, DATASET_DIR, LOG_DIR, CAPTURE_DIR]:
    os.makedirs(directory, exist_ok=True)

# Features mapping directly to CICIDS2017 column names (cleaned version without leading spaces)
# These 14 features are lightweight and can be easily computed in real-time by Scapy/PyShark
FEATURES = [
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count"
]

# Mapping of attack labels to Threat Levels (Risk Levels)
# The Random Forest will classify packets into these categories
THREAT_LEVELS = {
    "BENIGN": "LOW",
    "PortScan": "MEDIUM",
    "FTP-Patator": "HIGH",
    "SSH-Patator": "HIGH",
    "DDoS": "CRITICAL",
    "Bot": "CRITICAL",
    "Web Attack": "HIGH",
    "Infiltration": "CRITICAL"
}
