from collections import defaultdict
from scapy.all import IP, TCP, UDP
import config
from math import sqrt
from ipaddress import ip_address

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
            'inter_arrival_times_std': 0.0,
            'tcp_count': 0,
            'syn_count': 0,
            'rst_count': 0,
            'ack_count': 0,
            'ratio_tcp_syn': 0.0,
            'ratio_tcp_rst': 0.0,
            'ratio_tcp_ack': 0.0,
            'is_tcp': None #TCP=1, UDP=0, None=Unknown
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

        if protocol == 'TCP':
            stats['is_tcp'] = 1
            stats['tcp_count'] += 1
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN flag
                stats['syn_count'] += 1
            if flags & 0x04:  # RST flag
                stats['rst_count'] += 1
            if flags & 0x10:  # ACK flag
                stats['ack_count'] += 1
        else:
            stats['is_tcp'] = 0


        self.history_timestamp[flow_key].append(current_time)
        delta_time = current_time - self.history_timestamp[flow_key][-2] if len(self.history_timestamp[flow_key]) > 1 else 1.0
        self.delta_time_history[flow_key].append(delta_time)

        # Calculate inter-arrival time statistics
        deltas = self.delta_time_history[flow_key]
        stats['inter_arrival_times_moy'] = sum(deltas) / len(deltas) if deltas else 0.0
        means = stats['inter_arrival_times_moy']
        stats['inter_arrival_times_std'] = sqrt(sum((dt - means) ** 2 for dt in deltas) / len(deltas) if deltas else 0.0)

        return self.extract_features(packet, stats)

    def service_port_class(self, port: int) -> str:
        if port == 53:
            return "dns"
        if port == 80:
            return "http"
        if port == 443:
            return "https"
        if port == 5353:
            return "mdns"
        if port == 1900:
            return "ssdp"
        if port in (67, 68):
            return "dhcp"
        return "other"


    def service_one_hot(self, port: int) -> dict:
        service = self.service_port_class(port)
        one_hot = {
            "service_dns": 0,
            "service_http": 0,
            "service_https": 0,
            "service_mdns": 0,
            "service_ssdp": 0,
            "service_dhcp": 0,
            "service_other": 0,
        }
        one_hot[f"service_{service}"] = 1
        return one_hot

    def extract_features(self, packet, stats):
        duration = max(float(stats['last_time'] - stats['start_time']), 0.0)

        # Smooth rates to avoid extreme values when the flow is very recent.
        rate_window = max(duration, config.RATE_MIN_WINDOW_SECONDS)
        packet_rate = stats['packet_count'] / rate_window
        byte_rate = stats['byte_count'] / rate_window
        source_ip = packet[IP].src
        broadcast_or_multicast = 1 if ip_address(source_ip).is_multicast or ip_address(source_ip).is_broadcast else 0
        is_private_to_private = 1 if ip_address(source_ip).is_private and ip_address(packet[IP].dst).is_private else 0

        # Calculate TCP flag ratios
        if stats['tcp_count'] > 0:
            stats['ratio_tcp_syn'] = stats['syn_count'] / stats['tcp_count']
            stats['ratio_tcp_rst'] = stats['rst_count'] / stats['tcp_count']
            stats['ratio_tcp_ack'] = stats['ack_count'] / stats['tcp_count']

        transport_layer = packet[TCP] if stats['type'] == 'TCP' else packet[UDP]

        sport = transport_layer.sport
        dport = transport_layer.dport

        service_one_hot = self.service_one_hot(dport)

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': packet[TCP].flags if stats['type'] == 'TCP' else 0,
            'window_size': packet[TCP].window if stats['type'] == 'TCP' else 0,
            'type': stats['type'],
            'source_ip': source_ip,
            'destination_ip': packet[IP].dst,
            'source_port': sport,
            'destination_port': dport,
            'timestamp': float(packet.time),
            'inter_arrival_times_moy': stats['inter_arrival_times_moy'],
            'inter_arrival_times_std': stats['inter_arrival_times_std'],
            'ratio_tcp_syn': stats['ratio_tcp_syn'],
            'ratio_tcp_rst': stats['ratio_tcp_rst'],
            'ratio_tcp_ack': stats['ratio_tcp_ack'],
            'broadcast_or_multicast': broadcast_or_multicast,
            'is_private_to_private': is_private_to_private,
            'service_features': service_one_hot
        }
        