# IDS Intrusion Detection System

Real-time intrusion detection system (IDS) built with:
- network packet capture (Scapy)
- signature-based detection (SYN flood, port scan)
- anomaly detection (Isolation Forest)
- JSON alerting and file logging
- live visualization of normal/anomalous traffic points

## Features

### 1) Packet Capture
- Captures IP packets carrying TCP or UDP.
- Uses a thread-safe queue for packet processing.

### 2) Traffic Analysis
- Extracts per-flow features, including:
  - `packet_size`, `flow_duration`, `packet_rate`, `byte_rate`
  - `tcp_flags`, `window_size`, `is_tcp`
  - `inter_arrival_times_mean`, `inter_arrival_times_std`
  - `ratio_tcp_syn`, `ratio_tcp_rst`, `ratio_tcp_ack`
  - `broadcast_or_multicast`, `is_private_to_private`
  - one-hot service features: `service_dns/http/https/mdns/ssdp/dhcp/other`
  - rolling z-scores: `packet_size_zscore_rolling`, `packet_rate_zscore_rolling`

### 3) Signature-Based Detection
- Basic SYN flood rule.
- Stateful port-scan detection (window + cooldown).

### 4) Anomaly Detection
- Isolation Forest with incremental training.
- Periodic refit controlled by configuration.
- Anomaly threshold computed from a score percentile.
- Bounded training buffer to limit memory usage.

### 5) Alerts and Visualization
- Alerts are printed as JSON and logged in `ids_alerts.log`.
- Live plot: blue = normal, red = anomaly.

## Project Structure

- `packetcapture.py`: packet capture and queueing
- `trafficanalyzer.py`: feature extraction
- `detectionengine.py`: signature rules + Isolation Forest
- `alertsystem.py`: alert generation and logging
- `plotgraph.py`: live plotting
- `intrusiondetectionsystem.py`: orchestration
- `config.py`: runtime tuning parameters

## Requirements

- Python 3.10+
- Linux recommended for easier raw packet capture
- Elevated privileges may be required for sniffing (`sudo` or `setcap cap_net_raw` to your venv)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Edit `config.py` to tune:

- Interface:
  - `IFACE`
- Port scan detection:
  - `PORT_SCAN_WINDOW_SECONDS`
  - `PORT_SCAN_MIN_DISTINCT_PORTS`
  - `PORT_SCAN_ALERT_COOLDOWN_SECONDS`
- Isolation Forest:
  - `ANOMALY_CONTAMINATION`
  - `ANOMALY_MIN_TRAIN_SAMPLES`
  - `ANOMALY_MAX_TRAIN_SAMPLES`
  - `ANOMALY_REFIT_EVERY`
  - `ANOMALY_THRESHOLD_PERCENTILE`
- Rolling z-score:
  - `PACKET_SIZE_ZSCORE_WINDOW`
  - `PACKET_SIZE_ZSCORE_MIN_SAMPLES`
  - `PACKET_RATE_ZSCORE_WINDOW`
  - `PACKET_RATE_ZSCORE_MIN_SAMPLES`
  - `ZSCORE_EPSILON`

