import os
import threading
import time

import pandas as pd
from scapy import packet
from scapy.all import IP, TCP, sniff

from iptables_handler import IPtablesHandler
from utils import (FIREWALL_UPDATE_THREAD, LOG_FILE_NAME,
                   add_to_blocked_ip_set, is_ip_blocked, thread_safe_print,
                   write_to_log_file, IS_LOCALHOST)

# Valid flag combinations to track
VALID_FLAGS = {"S", "A", "F", "SA", "FA", "SAF"}

# Thresholds
PORT_SCANNING_THRESHOLD = 6
OS_FINGERPRINTING_THRESHOLD = 5
DNS_PORT = 53


class IDS_Service(threading.Thread):
    """
    Thread class to manage IDS service operations
    """

    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()

        self._port_scanning_source_timestamp_map = {}
        self._os_fingerprinting_source_timestamp_map = {}
        self._port_scanning_dataframe = pd.DataFrame(
            columns=["src_ip", "dst_port", "timestamp"]
        )
        self._os_fingerprinting_dataframe = pd.DataFrame(
            columns=["src_ip", "flags", "timestamp"]
        )


    def _clean_old_data(self, current_time) -> None:
        """Clean old time-based data"""

        # remove port scanning data older than 15s
        self._port_scanning_dataframe = self._port_scanning_dataframe[
            self._port_scanning_dataframe["timestamp"] >= current_time - 15
        ]

        # remove fingerprinting data older than 20s
        self._os_fingerprinting_dataframe = self._os_fingerprinting_dataframe[
            self._os_fingerprinting_dataframe["timestamp"] >= current_time - 20
        ]

        # remove attack data older than 30s
        self._port_scanning_source_timestamp_map = {
            ip: time for ip, time in self._port_scanning_source_timestamp_map.items() if time >= current_time - 30
        }


        # remove attack data older than 30s
        self._os_fingerprinting_source_timestamp_map = {
            ip: time for ip, time in self._os_fingerprinting_source_timestamp_map.items() if time >= current_time - 30
        }


    def _detect_port_scanning(self, src_ip: str) -> bool:
        """Return true if port scanning is detected"""
        scan_counts = self._port_scanning_dataframe.groupby("src_ip")[
            "dst_port"
        ].nunique()
        return scan_counts.get(
            src_ip, 0
        ) >= PORT_SCANNING_THRESHOLD and not is_ip_blocked(src_ip)


    def _detect_os_fingerprinting(self, src_ip: str) -> bool:
        """Return true if OS fingerprinting is detected"""
        unique_flags = self._os_fingerprinting_dataframe.groupby("src_ip")[
            "flags"
        ].nunique()
        return unique_flags.get(
            src_ip, 0
        ) >= OS_FINGERPRINTING_THRESHOLD and not is_ip_blocked(src_ip)


    def _block_ip_address(self, ip_addr: str) -> None:
        """Block an IP adress using IPtables thread"""
        global FIREWALL_UPDATE_THREAD

        add_to_blocked_ip_set(ip_addr)
        FIREWALL_UPDATE_THREAD = IPtablesHandler(ip_addr)
        FIREWALL_UPDATE_THREAD.start()


    def _ids_main_handler(self, packet: packet) -> None:
        """Capture packets and detect various possible attacks"""

        # capture TCP packets
        if packet.haslayer(IP) and packet.haslayer(TCP):
            # packet information
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            current_time = time.time()
            log_date = time.strftime("%d-%m-%y", time.localtime(current_time))
            log_time = time.strftime("%H:%M:%S", time.localtime(current_time))

            # filter packets
            if dst_port > 32768 or dst_port == DNS_PORT:
                return

            # port scanning detection
            if src_ip in self._port_scanning_source_timestamp_map:
                port_scanning_duration = (
                    current_time - self._port_scanning_source_timestamp_map[src_ip]
                )
            else:
                self._port_scanning_source_timestamp_map[src_ip] = current_time
                port_scanning_duration = 0

            line = f"{log_date}---{log_time}---TCP Port Scanning---{src_ip}---{dst_port}---{port_scanning_duration:.2f}\n"
            file_thread = threading.Thread(target=write_to_log_file, args=(line,))
            file_thread.start()

            # new entry for port scanning
            new_entry = pd.DataFrame([{"src_ip": src_ip, "dst_port": dst_port, "timestamp": current_time}])
            if not self._port_scanning_dataframe.empty:
                self._port_scanning_dataframe = pd.concat([self._port_scanning_dataframe, new_entry], ignore_index=True)
            else:
                self._port_scanning_dataframe = new_entry

            # os fingerprinting detection
            if any(flag in flags for flag in VALID_FLAGS):
                if src_ip in self._os_fingerprinting_source_timestamp_map:
                    os_fingerprinting_duration = (
                        current_time - self._os_fingerprinting_source_timestamp_map[src_ip]
                    )
                else:
                    self._os_fingerprinting_source_timestamp_map[src_ip] = current_time
                    os_fingerprinting_duration = 0

                line = f"{log_date}---{log_time}---OS Fingerprinting---{src_ip}---{flags}---{os_fingerprinting_duration:.2f}\n"
                file_thread = threading.Thread(target=write_to_log_file, args=(line,))
                file_thread.start()

                # new entry for os fingerprinting
                new_entry = pd.DataFrame([{"src_ip": src_ip, "flags": str(flags), "timestamp": current_time}])
                if not self._os_fingerprinting_dataframe.empty:
                    self._os_fingerprinting_dataframe = pd.concat([self._os_fingerprinting_dataframe, new_entry], ignore_index=True)
                else:
                    self._os_fingerprinting_dataframe = new_entry


            # cleanup of old data
            self._clean_old_data(current_time)

            # take action if port scanning is detected
            if self._detect_port_scanning(src_ip):
                thread_safe_print("[ALERT] Port Scanning detected!")
                self._block_ip_address(src_ip)

            # take action if os fingerprinting is detected
            if self._detect_os_fingerprinting(src_ip):
                thread_safe_print("[ALERT] OS Fingerprinting detected!")
                self._block_ip_address(src_ip)


    def run(self) -> None:
        """Thread main function"""
        thread_safe_print("Starting IDS service...")
        # create log file
        if not os.path.exists(LOG_FILE_NAME):
            with open(LOG_FILE_NAME, "w") as fp:
                os.chmod(LOG_FILE_NAME, 0o644)
                fp.write(
                    "Date---Time---Intrusion Type---Attacker IP---Targeted Ports/Flags---Time Span Of Attack\n"
                )

        if IS_LOCALHOST:
            while not self._stop_event.is_set():
                sniff(iface="lo", prn=self._ids_main_handler, store=False, timeout=5)
        else:
            while not self._stop_event.is_set():
                sniff(prn=self._ids_main_handler, store=False, timeout=5)


    def stop(self) -> None:
        thread_safe_print("Stopping IDS service...")
        self._stop_event.set()
