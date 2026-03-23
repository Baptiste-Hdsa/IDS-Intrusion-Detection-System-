from collections import defaultdict, deque
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
            'packet_rate': 0.0,
            'byte_rate': 0.0,
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
            'is_tcp': None, #TCP=1, UDP=0, None=Unknown
            'packet_size_zscore_rolling': 0.0,
            'packet_rate_zscore_rolling': 0.0
        })
        self.history_timestamp = defaultdict(list)
        self.delta_time_history = defaultdict(list)
        self.packet_size_history = defaultdict(
            lambda: deque(maxlen=config.PACKET_SIZE_ZSCORE_WINDOW)
        )

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
        self.packet_size_history[flow_key].append(len(packet))

        # Calculate inter-arrival time statistics
        delta_times = self.delta_time_history[flow_key]
        stats['inter_arrival_times_moy'] = sum(delta_times) / len(delta_times) if delta_times else 0.0
        means_times = stats['inter_arrival_times_moy']
        stats['inter_arrival_times_std'] = sqrt(sum((dt - means_times) ** 2 for dt in delta_times) / len(delta_times) if delta_times else 0.0)

        packet_sizes = self.packet_size_history[flow_key]
        stats['packet_size_zscore_rolling'] = self.zscore_rolling(flow_key, packet_sizes)
        packet_rate = stats['packet_count'] / max(current_time - stats['start_time'], config.RATE_MIN_WINDOW_SECONDS)
        stats['packet_rate_zscore_rolling'] = self.zscore_rolling(flow_key, packet_rate)

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

    def zscore_rolling(self, flow_key, packet_size):
        history = self.packet_size_history[flow_key]
        if len(history) < config.PACKET_SIZE_ZSCORE_MIN_SAMPLES:
            return 0.0
        mean_size = sum(history) / len(history)
        variance = sum((size - mean_size) ** 2 for size in history) / len(history)
        std_size = sqrt(variance)
        return (packet_size - mean_size) / (std_size if std_size > 0 else 1 )

    def extract_features(self, packet, stats):
        duration = max(float(stats['last_time'] - stats['start_time']), 0.0)

        # Smooth rates to avoid extreme values when the flow is very recent.
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        destination_addr = ip_address(destination_ip)
        broadcast_or_multicast = 1 if destination_addr.is_multicast or destination_ip == "255.255.255.255" else 0
        is_private_to_private = 1 if ip_address(source_ip).is_private and destination_addr.is_private else 0
        packet_size = len(packet)

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
            'packet_size': packet_size,
            'flow_duration': duration,
            'packet_rate': stats['packet_rate'],
            'byte_rate': stats['byte_rate'],
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
            'is_tcp': stats['is_tcp'],
            'broadcast_or_multicast': broadcast_or_multicast,
            'is_private_to_private': is_private_to_private,
            'service_features': service_one_hot,
            'packet_size_zscore_rolling': stats['packet_size_zscore_rolling'],
            'packet_rate_zscore_rolling': stats['packet_rate_zscore_rolling']
        }
        