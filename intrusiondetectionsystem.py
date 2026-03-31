import queue
from packetcapture import PacketCapture
from trafficanalyzer import TrafficAnalyzer
from detectionengine import DetectionEngine
from alertsystem import AlertSystem
from plotgraph import PlotGraph
from scapy.all import IP, TCP, UDP
import config

class IntrusionDetectionSystem:
    def __init__(self, interface=config.IFACE):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.plot_graph = PlotGraph()
        self.interface = interface
        self.counter = 0

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        print(f"[INFO] Anomaly detection warmup phase: disabled until {config.ANOMALY_WARMUP_SAMPLES} packets to stabilize Isolation Forest model")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                self.counter += 1
                print(f"Processed packet #{self.counter}")

                if features:
                    threats = self.detection_engine.detect_threats(features)
                    anomaly_threats = [threat for threat in threats if threat.get('type') == 'anomaly']
                    is_anomaly = bool(anomaly_threats)
                    anomaly_score = min((threat.get('score', 0.0) for threat in anomaly_threats), default=0.0)
                    anomaly_confidence = max((threat.get('confidence', 0.0) for threat in anomaly_threats), default=0.0)
                    self.plot_graph.add_data_point(features, is_anomaly, anomaly_score, anomaly_confidence)
                    self.plot_graph.update_plot()

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': threat.get('source_port'),
                            'destination_port': threat.get('destination_port')
                        }
                        self.alert_system.generate_alert(threat, packet_info)
                        
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.plot_graph.stop()
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()
