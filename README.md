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
- Elevated privileges may be required for sniffing (`sudo` or `setcap cap_net_raw ./your/venv` to your venv)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Attack Scenarios Explained

I have developed a script in Bash and Python, but I prefer not to publish for safety. However, you can create your own script with the internet or just use Nmap. I write this list just to know which attack you can develop and which IDS can detect.

1. `Warmup baseline (Isolation Forest training)`
Sends mixed benign-like UDP/TCP traffic on common service ports (53, 80, 443, 5353).
Goal: give the model a stable normal reference.

2. `SYN flood (TCP)`
High-rate SYN packets.
Mainly stresses: `packet_rate`, `byte_rate`, `tcp_flags`, `ratio_tcp_syn`.

3. `Port scan (TCP SYN)`
One SYN packet per target port.
Stresses destination-port diversity and can also trigger signature `port_scan`.

4. `Port scan (UDP)`
One UDP probe per target port.
Stresses destination-port diversity in UDP behavior.

5. `RST flood (fixed flow)`
Many RST packets on the same flow key (`src_ip,dst_ip,sport,dport`).
Stresses: `ratio_tcp_rst`, `tcp_flags`, `packet_rate`.

6. `ACK flood (fixed flow)`
Many ACK packets on the same flow.
Stresses: `ratio_tcp_ack`, `tcp_flags`, `window_size`, rate features.

7. `XMAS scan (TCP FPU)`
Unusual flag combination (FIN+PSH+URG).
Stresses unusual `tcp_flags` values and scan-like destination-port patterns.

8. `NULL scan (TCP no flags)`
TCP packets with no flags set.
Stresses rare `tcp_flags` profile and service/port behavior.

9. `UDP packet-size oscillation`
Alternates tiny payloads and near-MTU payloads on one stable flow.
Stresses: `packet_size`, `byte_rate`, `packet_size_zscore_rolling`.

10. `Multicast UDP burst (SSDP-like)`
High-rate traffic to `239.255.255.250:1900`.
Stresses: `broadcast_or_multicast`, `service_ssdp`, volume/rate.

11. `Service-hopping mixed traffic`
Rapid alternation across service classes: DNS/HTTP/HTTPS/mDNS/SSDP/DHCP/other,
with mixed UDP and TCP packets.
Stresses: one-hot service features, `is_tcp`, port distributions, flag/window variance.

12. `Inter-arrival jitter (UDP)`
Alternates micro-bursts and pauses on a fixed flow.
Stresses: `inter_arrival_times_mean`, `inter_arrival_times_std`, `packet_rate_zscore_rolling`.

13. `Normal UDP traffic (baseline)`
Simple low-rate baseline traffic for comparison and sanity checks.

14. `Full Isolation Forest stress profile`
Runs a complete chain: warmup, fixed-flow TCP anomalies, packet-size oscillation,
service hopping, multicast burst, and jitter tail.
Goal: exercise almost all anomaly features in one run.

### Feature Coverage (Isolation Forest)

The scenarios above are designed to collectively stress all anomaly inputs:

- Traffic volume: `packet_rate`, `byte_rate`
- Packet shape: `packet_size`, `packet_size_zscore_rolling`
- Flow timing: `inter_arrival_times_mean`, `inter_arrival_times_std`, `packet_rate_zscore_rolling`
- TCP behavior: `tcp_flags`, `window_size`, `ratio_tcp_syn`, `ratio_tcp_rst`, `ratio_tcp_ack`
- Transport/service context: `is_tcp`, `source_port`, `destination_port`, service one-hot features
- Network context: `broadcast_or_multicast`, `is_private_to_private`
