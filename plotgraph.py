from collections import deque
from typing import Deque, Optional

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure

import config

class PlotGraph:
    def __init__(self):
        self.traffic_data: Deque[dict] = deque(maxlen=config.PLOT_MAX_POINTS)
        self.points_since_draw = 0
        self.figure: Optional[Figure] = None
        self.axes: Optional[list[Axes]] = None

    def ensure_figure(self):
        if self.figure is not None:
            return
        plt.ion()
        self.figure, axes = plt.subplots(2, 2, figsize=(12, 8))
        self.axes = list(axes.flatten())

    def add_data_point(self, features, is_anomaly, anomaly_score=0.0, anomaly_confidence=0.0):
        self.traffic_data.append({
            'packet_rate': features['packet_rate'],
            'byte_rate': features['byte_rate'],
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'anomaly_confidence': float(anomaly_confidence),
        })
        self.points_since_draw += 1

    def _rolling_anomaly_rate(self, anomaly_flags):
        window = max(1, config.PLOT_ANOMALY_RATE_WINDOW)
        running = 0
        rolling = []

        for idx, flag in enumerate(anomaly_flags):
            running += 1 if flag else 0
            if idx >= window:
                running -= 1 if anomaly_flags[idx - window] else 0

            current_window_size = min(idx + 1, window)
            rolling.append(100.0 * running / current_window_size)

        return rolling

    def update_plot(self):
        self.ensure_figure()
        if not self.traffic_data or self.figure is None or self.axes is None:
            return

        if self.points_since_draw < config.PLOT_UPDATE_EVERY:
            return
        self.points_since_draw = 0

        points = list(self.traffic_data)
        anomaly_flags = [point['is_anomaly'] for point in points]
        anomaly_scores = [point['anomaly_score'] for point in points]

        normal_points = [point for point in points if not point['is_anomaly']]
        anomaly_points = [point for point in points if point['is_anomaly']]

        ax_scatter, ax_score, ax_rate, ax_hist = self.axes

        ax_scatter.clear()
        ax_scatter.set_title('Traffic Scatter')
        ax_scatter.set_xlabel('Packet Rate (packets/sec)')
        ax_scatter.set_ylabel('Byte Rate (bytes/sec)')
        ax_scatter.grid(True)

        if normal_points:
            ax_scatter.scatter(
                [point['packet_rate'] for point in normal_points],
                [point['byte_rate'] for point in normal_points],
                c='blue',
                s=15,
                alpha=0.5,
                label='Normal',
            )

        if anomaly_points:
            ax_scatter.scatter(
                [point['packet_rate'] for point in anomaly_points],
                [point['byte_rate'] for point in anomaly_points],
                c='red',
                s=25,
                alpha=0.9,
                label='Anomaly',
            )

        if normal_points or anomaly_points:
            ax_scatter.legend(loc='upper right')

        ax_score.clear()
        ax_score.set_title('Isolation Forest Score (Live)')
        ax_score.set_xlabel('Sample Index')
        ax_score.set_ylabel('Score')
        ax_score.grid(True)
        ax_score.plot(anomaly_scores, color='tab:orange', linewidth=1)
        ax_score.axhline(0.0, color='gray', linestyle='--', linewidth=1)

        ax_rate.clear()
        ax_rate.set_title('Rolling Anomaly Rate (%)')
        ax_rate.set_xlabel('Sample Index')
        ax_rate.set_ylabel('Rate (%)')
        ax_rate.grid(True)
        rolling_rate = self._rolling_anomaly_rate(anomaly_flags)
        ax_rate.plot(rolling_rate, color='tab:red', linewidth=1.2)
        ax_rate.set_ylim(0, 100)

        ax_hist.clear()
        ax_hist.set_title('Anomaly Score Distribution')
        ax_hist.set_xlabel('Score')
        ax_hist.set_ylabel('Count')
        ax_hist.grid(True)
        if anomaly_scores:
            ax_hist.hist(anomaly_scores, bins=25, color='tab:purple', alpha=0.7)

        anomaly_count = sum(1 for flag in anomaly_flags if flag)
        normal_count = len(points) - anomaly_count
        if points:
            ratio = 100.0 * anomaly_count / len(points)
            self.figure.suptitle(
                f'IDS Live Dashboard | Total={len(points)} Normal={normal_count} Anomaly={anomaly_count} ({ratio:.2f}%)',
                fontsize=10,
            )

        self.figure.tight_layout()
        self.figure.canvas.draw_idle()
        plt.pause(0.001)

    def stop(self):
        if self.figure is not None:
            plt.close(self.figure)
            self.figure = None
            self.axes = None
    
