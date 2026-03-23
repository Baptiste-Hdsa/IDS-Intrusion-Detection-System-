# IDS Intrusion Detection System

Real-time intrusion detection system (IDS) built with:
- network packet capture (Scapy)
- signature-based detection (SYN flood, port scan)
- anomaly detection (Isolation Forest)
- JSON alerting and file logging
- live visualization of normal/anomalous traffic points

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
