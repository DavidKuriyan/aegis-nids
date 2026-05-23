import pandas as pd
import numpy as np
import os
import sys

# Ensure config path is visible
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def generate_mock_dataset(num_rows=30000):
    """
    Generates a realistic CICIDS2017-style dataset for training the Random Forest NIDS.
    
    ALL flow_duration values are in MICROSECONDS (matching CICIDS2017 standard).
    flow_bytes_sec and flow_pkts_sec are derived correctly from microsecond durations.
    
    Bug fixes vs previous version:
    - PortScan had flow_duration = uniform(1,100) μs → pkts/sec = 10,000,000 (wrong!)
      Now: flow_duration = uniform(100_000, 2_000_000) μs (0.1s – 2s per scan flow)
    - DDoS had duration too low → pkts/sec = millions (unrealistic)
    - fwd_pkt_len_mean was recalculated at the end correctly but intermediate var was wrong
    - Added random noise to all features to prevent overfitting to exact values
    - Increased dataset size to 30,000 rows for better generalization
    """
    print(f"Generating simulated CICIDS2017-style dataset with {num_rows} records...")
    np.random.seed(42)

    # Class distribution matching approximate CICIDS2017 proportions
    labels_pool   = ["BENIGN", "PortScan", "DDoS", "Bot", "FTP-Patator", "SSH-Patator", "Web Attack", "Infiltration"]
    label_weights = [0.60,     0.10,       0.12,   0.05,  0.04,          0.04,          0.03,         0.02]

    selected_labels = np.random.choice(labels_pool, size=num_rows, p=label_weights)

    data = []

    for label in selected_labels:
        # -----------------------------------------------------------------------
        # DEFAULT VALUES (overridden per-label below)
        # -----------------------------------------------------------------------
        dest_port        = int(np.random.choice([80, 443, 53, 123, 22, 21]))
        protocol         = int(np.random.choice([6, 17]))   # TCP=6, UDP=17
        # flow_duration in MICROSECONDS
        flow_duration    = float(np.random.uniform(50_000, 500_000))  # 0.05s – 0.5s
        tot_fwd_pkts     = int(np.random.randint(1, 20))
        fwd_pkt_len_max  = float(np.random.uniform(100, 1400))
        fwd_pkt_len_min  = float(np.random.uniform(20, 80))
        syn_flag         = 0
        rst_flag         = 0
        psh_flag         = 0
        ack_flag         = 1

        # -----------------------------------------------------------------------
        # PER-CLASS SIGNATURES
        # -----------------------------------------------------------------------
        if label == "BENIGN":
            # Standard HTTP/HTTPS/DNS traffic — moderate flow sizes
            dest_port = int(np.random.choice([80, 443, 53, 8080, 123]))
            if dest_port == 53:
                protocol      = 17  # DNS is UDP
                flow_duration = float(np.random.uniform(1_000, 20_000))   # 1ms – 20ms
                tot_fwd_pkts  = int(np.random.randint(1, 4))
                fwd_pkt_len_max = float(np.random.uniform(40, 120))
                fwd_pkt_len_min = float(np.random.uniform(20, 40))
                syn_flag = rst_flag = psh_flag = ack_flag = 0
            elif dest_port in [80, 443, 8080]:
                protocol      = 6
                flow_duration = float(np.random.uniform(100_000, 2_000_000))  # 0.1s – 2s
                tot_fwd_pkts  = int(np.random.randint(3, 25))
                fwd_pkt_len_max = float(np.random.uniform(500, 1400))
                fwd_pkt_len_min = float(np.random.uniform(40, 100))
                psh_flag = int(np.random.choice([0, 1], p=[0.3, 0.7]))
                ack_flag = 1
            else:
                protocol      = int(np.random.choice([6, 17]))
                flow_duration = float(np.random.uniform(50_000, 800_000))
                tot_fwd_pkts  = int(np.random.randint(2, 15))
                ack_flag      = 1

        elif label == "PortScan":
            # Port scanning: SYN packets to many ports, 1 pkt per flow, very short duration
            # flow_duration per individual scan flow is SHORT but not absurdly short
            dest_port     = int(np.random.randint(1, 65535))
            protocol      = 6
            # 0.05ms – 50ms per individual scan probe (not 0.000001ms)
            flow_duration = float(np.random.uniform(50, 50_000))
            tot_fwd_pkts  = 1
            fwd_pkt_len_max = float(np.random.choice([0, 40, 54, 64]))
            fwd_pkt_len_min = fwd_pkt_len_max
            syn_flag      = 1
            rst_flag      = int(np.random.choice([0, 1], p=[0.6, 0.4]))
            psh_flag      = 0
            ack_flag      = 0

        elif label == "DDoS":
            # DDoS flood: very high packet counts, high throughput, short bursts
            dest_port     = int(np.random.choice([80, 443, 53, 8080]))
            protocol      = int(np.random.choice([6, 17], p=[0.6, 0.4]))
            # 0.5s – 10s burst window
            flow_duration = float(np.random.uniform(500_000, 10_000_000))
            tot_fwd_pkts  = int(np.random.randint(80, 500))
            fwd_pkt_len_max = float(np.random.choice([64.0, 512.0, 1024.0, 1400.0]))
            fwd_pkt_len_min = fwd_pkt_len_max * 0.9  # uniform packet sizes (flooding pattern)
            if protocol == 6:
                syn_flag  = int(np.random.choice([0, 1], p=[0.3, 0.7]))
                ack_flag  = int(np.random.choice([0, 1], p=[0.7, 0.3]))
            else:
                syn_flag = rst_flag = psh_flag = ack_flag = 0

        elif label == "Bot":
            # Botnet C&C: specific ports, long idle flows, periodic small bursts
            dest_port     = int(np.random.choice([6667, 8080, 10000, 4444, 1337]))
            protocol      = 6
            # 10s – 2min C&C session
            flow_duration = float(np.random.uniform(10_000_000, 120_000_000))
            tot_fwd_pkts  = int(np.random.randint(5, 40))
            fwd_pkt_len_max = float(np.random.uniform(100, 300))
            fwd_pkt_len_min = float(np.random.uniform(20, 60))
            psh_flag      = 1
            ack_flag      = 1

        elif label == "FTP-Patator":
            # FTP brute force: port 21, many short TCP sessions
            dest_port     = 21
            protocol      = 6
            # 1ms – 5ms per attempt
            flow_duration = float(np.random.uniform(1_000, 5_000))
            tot_fwd_pkts  = int(np.random.randint(4, 12))
            fwd_pkt_len_max = float(np.random.uniform(60, 180))
            fwd_pkt_len_min = float(np.random.uniform(20, 40))
            syn_flag      = 0
            psh_flag      = 1
            ack_flag      = 1

        elif label == "SSH-Patator":
            # SSH brute force: port 22, slightly longer negotiation flows
            dest_port     = 22
            protocol      = 6
            # 2ms – 8ms per attempt
            flow_duration = float(np.random.uniform(2_000, 8_000))
            tot_fwd_pkts  = int(np.random.randint(6, 18))
            fwd_pkt_len_max = float(np.random.uniform(80, 200))
            fwd_pkt_len_min = float(np.random.uniform(20, 40))
            syn_flag      = 0
            psh_flag      = 1
            ack_flag      = 1

        elif label == "Web Attack":
            # SQL injection / XSS: large HTTP request payloads, port 80/8080
            dest_port     = int(np.random.choice([80, 8080]))
            protocol      = 6
            # 5ms – 30ms per web request
            flow_duration = float(np.random.uniform(5_000, 30_000))
            tot_fwd_pkts  = int(np.random.randint(10, 50))
            # Abnormally large fwd payload (crafted SQL/JS injection)
            fwd_pkt_len_max = float(np.random.uniform(1200, 3000))
            fwd_pkt_len_min = float(np.random.uniform(200, 600))
            psh_flag      = 1
            ack_flag      = 1

        elif label == "Infiltration":
            # Backdoor/exfiltration: high-port, very long sessions, large data transfer
            dest_port     = int(np.random.randint(1024, 65535))
            protocol      = 6
            # 100s – 500s exfil session
            flow_duration = float(np.random.uniform(100_000_000, 500_000_000))
            tot_fwd_pkts  = int(np.random.randint(30, 120))
            fwd_pkt_len_max = float(np.random.uniform(1000, 4000))
            fwd_pkt_len_min = float(np.random.uniform(40, 200))
            psh_flag      = 1
            ack_flag      = 1

        # -----------------------------------------------------------------------
        # DERIVED FIELDS (computed after per-label overrides)
        # -----------------------------------------------------------------------
        # Add realistic noise to packet counts and lengths
        noise_scale        = 0.05  # 5% noise
        tot_fwd_pkts       = max(1, int(tot_fwd_pkts * np.random.uniform(1 - noise_scale, 1 + noise_scale)))
        fwd_pkt_len_max    = max(0.0, fwd_pkt_len_max * np.random.uniform(0.95, 1.05))
        fwd_pkt_len_min    = max(0.0, min(fwd_pkt_len_min * np.random.uniform(0.95, 1.05), fwd_pkt_len_max))
        fwd_pkt_len_mean   = (fwd_pkt_len_max + fwd_pkt_len_min) / 2.0

        # Total fwd bytes = mean_len * pkt_count with noise
        tot_len_fwd_pkts   = float(fwd_pkt_len_mean * tot_fwd_pkts * np.random.uniform(0.9, 1.1))
        tot_len_fwd_pkts   = max(0.0, tot_len_fwd_pkts)

        # Convert flow duration from microseconds to seconds for rate calculations
        # Add tiny epsilon to prevent division by zero
        flow_duration_sec  = max(flow_duration / 1_000_000.0, 1e-9)

        # flow_bytes_sec: total bytes (fwd + bwd approx) / duration
        # We approximate bwd bytes as a fraction of fwd for simplicity
        approx_total_bytes = tot_len_fwd_pkts * np.random.uniform(1.0, 2.0)  # bwd adds ~0-100% more
        flow_bytes_sec     = approx_total_bytes / flow_duration_sec

        # flow_pkts_sec: total packets / duration
        approx_total_pkts  = int(tot_fwd_pkts * np.random.uniform(1.0, 1.5))
        flow_pkts_sec      = approx_total_pkts / flow_duration_sec

        # Cap unrealistic values (prevent inf/nan in edge cases)
        flow_bytes_sec = min(flow_bytes_sec, 1e9)  # Max 1 GB/s
        flow_pkts_sec  = min(flow_pkts_sec,  1e6)  # Max 1M pkts/s

        row = {
            "Destination Port":           int(dest_port),
            "Protocol":                   int(protocol),
            "Flow Duration":              float(flow_duration),
            "Total Fwd Packets":          int(tot_fwd_pkts),
            "Total Length of Fwd Packets":float(tot_len_fwd_pkts),
            "Fwd Packet Length Max":      float(fwd_pkt_len_max),
            "Fwd Packet Length Min":      float(fwd_pkt_len_min),
            "Fwd Packet Length Mean":     float(fwd_pkt_len_mean),
            "Flow Bytes/s":               float(flow_bytes_sec),
            "Flow Packets/s":             float(flow_pkts_sec),
            "SYN Flag Count":             int(syn_flag),
            "RST Flag Count":             int(rst_flag),
            "PSH Flag Count":             int(psh_flag),
            "ACK Flag Count":             int(ack_flag),
            "Label":                      label
        }
        data.append(row)

    df = pd.DataFrame(data)

    # Validate: remove any NaN/Inf rows that slipped through
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    os.makedirs(config.DATASET_DIR, exist_ok=True)
    df.to_csv(config.DATASET_PATH, index=False)

    print(f"\nDataset generated successfully: {config.DATASET_PATH}")
    print(f"Total rows: {len(df)}")
    print("\nClass distribution:")
    print(df["Label"].value_counts())
    print("\nFeature statistics (sanity check):")
    print(df[["Flow Bytes/s", "Flow Packets/s", "Flow Duration"]].describe())

if __name__ == "__main__":
    generate_mock_dataset()
