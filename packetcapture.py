from scapy.all import sniff, IP, TCP, UDP
import threading
import queue
import config

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            self.packet_queue.put(packet)

    def start_capture(self, interface=config.IFACE):
        def capture_thread():
            # Run sniff in short time slices so stop_capture is checked even when no new packet arrives.
            while not self.stop_capture.is_set():
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=0,
                    stop_filter=lambda _: self.stop_capture.is_set()
                )

        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join(timeout=2)