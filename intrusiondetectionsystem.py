import queue
from packetcapture import PacketCapture
from trafficanalyzer import TrafficAnalyzer
from detectionengine import DetectionEngine
from alertsystem import AlertSystem
from scapy.all import IP, TCP, UDP
import config


class IntrusionDetectionSystem:
    def __init__(self, interface=config.IFACE):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    transport_layer = packet[TCP] if features['type'] == 'TCP' else packet[UDP]
                    features.update({
                        'source_ip': packet[IP].src,
                        'destination_ip': packet[IP].dst,
                        'source_port': transport_layer.sport,
                        'destination_port': transport_layer.dport,
                        'timestamp': float(packet.time)
                    })
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': transport_layer.sport,
                            'destination_port': transport_layer.dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()