from scapy.all import sniff
import threading
import queue
import config

packet_queue = queue.Queue()
stop_event = threading.Event()


def capture_packets():
    while not stop_event.is_set():
        sniff(
            iface=config.IFACE,
            prn=lambda packet: packet_queue.put(packet),
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )


def print_packets():
    while not stop_event.is_set() or not packet_queue.empty():
        try:
            packet = packet_queue.get(timeout=0.5)
            print(packet)
        except queue.Empty:
            continue


def main():
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    printer_thread = threading.Thread(target=print_packets, daemon=True)

    capture_thread.start()
    printer_thread.start()

    print("Capture en cours. Appuie sur Entree ou Ctrl+C pour arreter...")
    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        capture_thread.join(timeout=2)
        printer_thread.join(timeout=2)
        print("Capture arretee.")


if __name__ == "__main__":
    main()
