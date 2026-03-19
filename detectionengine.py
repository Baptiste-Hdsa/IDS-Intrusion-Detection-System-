# from sklearn.ensemble import IsolationForest
# from sklearn.exceptions import NotFittedError
import numpy as np
from collections import defaultdict, deque

class DetectionEngine:
    def __init__(self):
        # Isolation Forest temporairement désactivé.
        # self.anomaly_detector = IsolationForest(
        #     contamination=0.1,
        #     random_state=42
        # )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.port_scan_window_seconds = 10 # Time in seconds window to track ports for port scan detection
        self.port_scan_min_distinct_ports = 10
        self.port_scan_alert_cooldown_seconds = 5
        self.source_port_history = defaultdict(deque)
        self.last_port_scan_alert_time = {}

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN flag
                    features['packet_rate'] > 100
                )
            }
        }

    def detect_port_scan(self, features):
        source_ip = features.get('source_ip')
        destination_port = features.get('destination_port')
        packet_time = features.get('timestamp')

        if source_ip is None or destination_port is None or packet_time is None:
            return None

        self.source_port_history[source_ip].append((packet_time, destination_port))
        history = self.source_port_history[source_ip]

        window_start = packet_time - self.port_scan_window_seconds
        while history and history[0][0] < window_start:
            history.popleft()

        distinct_ports = {port for _, port in history}
        if len(distinct_ports) < self.port_scan_min_distinct_ports:
            return None

        last_alert_time = self.last_port_scan_alert_time.get(source_ip)
        if last_alert_time is not None and (packet_time - last_alert_time) < self.port_scan_alert_cooldown_seconds:
            return None

        self.last_port_scan_alert_time[source_ip] = packet_time
        return {
            'type': 'signature',
            'rule': 'port_scan',
            'confidence': 1.0,
            'distinct_ports': len(distinct_ports),
            'window_seconds': self.port_scan_window_seconds
        }

    def train_anomaly_detector(self, normal_traffic_data):
        # Isolation Forest temporairement désactivé.
        # self.anomaly_detector.fit(normal_traffic_data)
        pass

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })
        # Port scan detection
        port_scan_threat = self.detect_port_scan(features)
        if port_scan_threat:
            threats.append(port_scan_threat)

        # Isolation Forest temporairement désactivé.
        # feature_vector = np.array([[
        #     features['packet_size'],
        #     features['packet_rate'],
        #     features['byte_rate']
        # ]])
        #
        # try:
        #     anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        #     if anomaly_score < -0.5:  # Threshold for anomaly detection
        #         threats.append({
        #             'type': 'anomaly',
        #             'score': anomaly_score,
        #             'confidence': min(1.0, abs(anomaly_score))
        #         })
        # except NotFittedError:
        #     # Skip anomaly detection until the model is trained.
        #     pass

        return threats