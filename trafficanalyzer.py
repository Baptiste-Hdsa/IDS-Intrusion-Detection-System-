from collections import defaultdict
from scapy.all import IP, TCP, UDP

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'type': ''
        })

    def analyze_packet(self, packet):
        if IP not in packet:
            return None

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

        if not stats['start_time']:
            stats['start_time'] = current_time
        stats['last_time'] = current_time

        return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time']
        if stats['packet_count'] < 99:
            safe_duration = 1
        else:
            safe_duration = duration

        #print(f"packet_rate = {stats['packet_count']} / {safe_duration}")
        #print(f"byte_rate = {stats['byte_count']} / {safe_duration}")
        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / safe_duration,
            'byte_rate': stats['byte_count'] / safe_duration,
            'tcp_flags': packet[TCP].flags if stats['type'] == 'TCP' else 0,
            'window_size': packet[TCP].window if stats['type'] == 'TCP' else 0,
            'type': stats['type']
        }
        