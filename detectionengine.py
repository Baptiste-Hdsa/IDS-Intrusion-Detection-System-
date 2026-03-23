from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
import numpy as np
from collections import defaultdict, deque
import config

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=config.ANOMALY_CONTAMINATION,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = deque(maxlen=config.ANOMALY_MAX_TRAIN_SAMPLES)
        self.port_scan_window_seconds = config.PORT_SCAN_WINDOW_SECONDS
        self.port_scan_min_distinct_ports = config.PORT_SCAN_MIN_DISTINCT_PORTS
        self.port_scan_alert_cooldown_seconds = config.PORT_SCAN_ALERT_COOLDOWN_SECONDS
        self.source_port_history = defaultdict(deque)
        self.last_port_scan_alert_time = {}
        self.min_train_samples = config.ANOMALY_MIN_TRAIN_SAMPLES
        self.refit_every = config.ANOMALY_REFIT_EVERY
        self.anomaly_threshold_percentile = config.ANOMALY_THRESHOLD_PERCENTILE
        self.anomaly_threshold = None
        self.seen_packets = 0
        self.is_model_fitted = False

    @staticmethod
    def safe_float(value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

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
    
    def anomaly_detection(self, features, threats):
        service_features = features.get("service_features", {})
        f = self.safe_float
        x = np.array([[
            f(features.get("packet_size")),
            f(features.get('source_port')),
            f(features.get('destination_port')),
            f(features.get("packet_rate")),
            f(features.get("byte_rate")),
            f(features.get("tcp_flags")),
            f(features.get("window_size")),
            f(features.get("inter_arrival_times_mean")),
            f(features.get("inter_arrival_times_std")),
            f(features.get("ratio_tcp_syn")),
            f(features.get("ratio_tcp_rst")),
            f(features.get("ratio_tcp_ack")),
            f(features.get("is_tcp")),
            f(features.get("broadcast_or_multicast")),
            f(features.get("is_private_to_private")),
            f(service_features.get("service_dns")),
            f(service_features.get("service_http")),
            f(service_features.get("service_https")),
            f(service_features.get("service_mdns")),
            f(service_features.get("service_ssdp")),
            f(service_features.get("service_dhcp")),
            f(service_features.get("service_other")),
            f(features.get("packet_size_zscore_rolling")),
            f(features.get("packet_rate_zscore_rolling"))
        ]], dtype=float)

        self.seen_packets += 1
        self.training_data.append(x.flatten())

        if len(self.training_data) < self.min_train_samples:
            return

        if (not self.is_model_fitted) or (self.seen_packets % self.refit_every == 0):
            train_arr = np.array(self.training_data, dtype=float)
            self.anomaly_detector.fit(train_arr)
            train_scores = self.anomaly_detector.score_samples(train_arr)
            self.anomaly_threshold = float(
                np.percentile(train_scores, self.anomaly_threshold_percentile)
            )
            self.is_model_fitted = True

        try:
            if self.anomaly_threshold is None:
                return

            current_score = float(self.anomaly_detector.score_samples(x)[0])

            if current_score < self.anomaly_threshold:
                threats.append({
                    "type": "anomaly",
                    "score": current_score,
                    "confidence": min(1.0, abs(current_score))
                })
        except NotFittedError:
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

        # Anomaly-based detection
        self.anomaly_detection(features, threats)

        return threats