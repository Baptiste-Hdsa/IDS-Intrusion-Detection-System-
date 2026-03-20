import matplotlib.pyplot as plt
from typing import Optional
from matplotlib.axes import Axes
from matplotlib.figure import Figure

class PlotGraph:
    def __init__(self):
        self.traffic_data = []
        self.max_points = 1000
        self.figure: Optional[Figure] = None
        self.axis: Optional[Axes] = None

    def ensure_figure(self):
        if self.figure is not None:
            return
        plt.ion()
        self.figure, self.axis = plt.subplots(figsize=(10, 6))

    def add_data_point(self, features, is_anomaly):
        self.traffic_data.append({
            'packet_rate': features['packet_rate'],
            'byte_rate': features['byte_rate'],
            'is_anomaly': bool(is_anomaly),
        })
        if len(self.traffic_data) > self.max_points:
            self.traffic_data = self.traffic_data[-self.max_points:]

    def update_plot(self):
        self.ensure_figure()
        if not self.traffic_data or self.figure is None or self.axis is None:
            return

        normal_points = [point for point in self.traffic_data if not point['is_anomaly']]
        anomaly_points = [point for point in self.traffic_data if point['is_anomaly']]

        self.axis.clear()
        self.axis.set_title('Traffic Points (Blue=Normal, Red=Anomaly)')
        self.axis.set_xlabel('Packet Rate (packets/sec)')
        self.axis.set_ylabel('Byte Rate (bytes/sec)')
        self.axis.grid(True)

        if normal_points:
            self.axis.scatter(
                [point['packet_rate'] for point in normal_points],
                [point['byte_rate'] for point in normal_points],
                c='blue',
                s=20,
                alpha=0.7,
                label='Normal',
            )

        if anomaly_points:
            self.axis.scatter(
                [point['packet_rate'] for point in anomaly_points],
                [point['byte_rate'] for point in anomaly_points],
                c='red',
                s=30,
                alpha=0.9,
                label='Anomaly',
            )

        if normal_points or anomaly_points:
            self.axis.legend(loc='upper right')

        self.figure.canvas.draw_idle()
        plt.pause(0.001)

    def stop(self):
        if self.figure is not None:
            plt.close(self.figure)
            self.figure = None
            self.axis = None
    
