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

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                
                if features:
                    threats = self.detection_engine.detect_threats(features)
                    is_anomaly = any(threat.get('type') == 'anomaly' for threat in threats)
                    self.plot_graph.add_data_point(features, is_anomaly)
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