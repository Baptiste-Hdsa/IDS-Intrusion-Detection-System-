from collections import defaultdict
from scapy.all import IP, TCP, UDP
import config

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'type': '',
            'inter_arrival_times_moy': 0.0,
            'inter_arrival_times_std': 0.0
        })
        self.history_timestamp = defaultdict(list)
        self.delta_time_history = defaultdict(list)

    def analyze_packet(self, packet):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if TCP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            protocol = 'TCP'
        elif UDP in packet:
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            protocol = 'UDP'
        else:
            return None

        flow_key = (ip_src, ip_dst, port_src, port_dst)

        # Update flow statistics
        stats = self.flow_stats[flow_key]
        stats['type'] = protocol
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        current_time = packet.time

        if stats['start_time'] is None:
            stats['start_time'] = current_time
        stats['last_time'] = current_time
        

        self.history_timestamp[flow_key].append(current_time)
        delta_time = current_time - self.history_timestamp[flow_key][-2] if len(self.history_timestamp[flow_key]) > 1 else 1.0
        self.delta_time_history[flow_key].append(delta_time)

        deltas = self.delta_time_history[flow_key]
        stats['inter_arrival_times_moy'] = sum(deltas) / len(deltas) if deltas else 0.0
        means = stats['inter_arrival_times_moy']
        stats['inter_arrival_times_std'] = sum((dt - means) ** 2 for dt in deltas) / len(deltas) if deltas else 0.0

        return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        duration = max(float(stats['last_time'] - stats['start_time']), 0.0)

        # Smooth rates to avoid extreme values when the flow is very recent.
        rate_window = max(duration, config.RATE_MIN_WINDOW_SECONDS)
        packet_rate = stats['packet_count'] / rate_window
        byte_rate = stats['byte_count'] / rate_window
        transport_layer = packet[TCP] if stats['type'] == 'TCP' else packet[UDP]


        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': packet[TCP].flags if stats['type'] == 'TCP' else 0,
            'window_size': packet[TCP].window if stats['type'] == 'TCP' else 0,
            'type': stats['type'],
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'source_port': transport_layer.sport,
            'destination_port': transport_layer.dport,
            'timestamp': float(packet.time),
            'inter_arrival_times_moy': stats['inter_arrival_times_moy'],
            'inter_arrival_times_std': stats['inter_arrival_times_std']
        }
        