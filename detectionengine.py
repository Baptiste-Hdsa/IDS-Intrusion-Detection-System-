from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
import numpy as np
from collections import defaultdict, deque
import config

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1, # proportion of outliers in the data set
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.port_scan_window_seconds = config.PORT_SCAN_WINDOW_SECONDS
        self.port_scan_min_distinct_ports = config.PORT_SCAN_MIN_DISTINCT_PORTS
        self.port_scan_alert_cooldown_seconds = config.PORT_SCAN_ALERT_COOLDOWN_SECONDS
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
        destination_ip = features.get('destination_ip')
        destination_port = features.get('destination_port')
        packet_time = features.get('timestamp')
        protocol = features.get('type')
        
        if protocol == 'TCP' and features.get('tcp_flags') != 2:
            return None

        if source_ip is None or destination_ip is None or destination_port is None or packet_time is None or protocol is None:
            return None

        scan_key = (source_ip, destination_ip, protocol)

        self.source_port_history[scan_key].append((packet_time, destination_port))
        history = self.source_port_history[scan_key]

        window_start = packet_time - self.port_scan_window_seconds
        while history and history[0][0] < window_start:
            history.popleft()

        distinct_ports = {port for _, port in history}
        if len(distinct_ports) < self.port_scan_min_distinct_ports:
            return None

        last_alert_time = self.last_port_scan_alert_time.get(scan_key)
        if last_alert_time is not None and (packet_time - last_alert_time) < self.port_scan_alert_cooldown_seconds:
            return None

        self.last_port_scan_alert_time[scan_key] = packet_time
        return {
            'type': 'signature',
            'rule': 'port_scan',
            'confidence': 1.0,
            'distinct_ports': len(distinct_ports),
            'window_seconds': self.port_scan_window_seconds,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'protocol': protocol
        }

    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

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

        # Anomaly-based detection
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])
        self.training_data.append(feature_vector.flatten())
        clf = self.anomaly_detector.fit(self.training_data)
        
        try:
            training_data_array = np.array(self.training_data)
            anomaly_score = clf.score_samples(training_data_array)
            threshold = np.percentile(anomaly_score, 2)
            anomaly_mask = anomaly_score < threshold
            if np.any(anomaly_mask):
                threats.append({
                    'type': 'anomaly',
                    'score': float(np.min(anomaly_score[anomaly_mask])),
                    'confidence': min(1.0, abs(float(np.min(anomaly_score[anomaly_mask]))))
                })
        except NotFittedError:
            # Skip anomaly detection until the model is trained.
            pass
        return threats