import threading
from utils import thread_safe_print, IS_LOCALHOST
from scapy.all import sniff, IP, TCP, UDP
from scapy import packet


class View_Traffic_Thread(threading.Thread):
    """
    Thread to show live traffic to the user
    """

    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()

    def _packet_callback(self, packet: packet) -> None:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto  # Protocol number (6 = TCP, 17 = UDP)

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                thread_safe_print(
                    f"[INFO] Captured TCP packet transmitted from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                )
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                thread_safe_print(
                    f"[INFO] Captured UDP packet transmitted from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                )
            else:
                thread_safe_print(
                    f"[INFO] Captured packet with protocol {protocol} transmitted from {src_ip} to {dst_ip}"
                )

    def run(self):
        thread_safe_print(
            "\nShowing live traffic; press Ctrl + Z to return to menu...\n"
        )
        if IS_LOCALHOST:
            while not self._stop_event.is_set():
                sniff(iface="lo", prn=self._packet_callback, store=False, timeout=1)
            thread_safe_print("")
        else:
            while not self._stop_event.is_set():
                sniff(prn=self._packet_callback, store=False, timeout=1)
            thread_safe_print("")

    def stop(self):
        self._stop_event.set()
