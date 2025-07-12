import signal
from copy import deepcopy

import pandas as pd

from ids_service import IDS_Service
from iptables_handler import update_firewall_unblock_ip
from utils import *
from view_traffic import View_Traffic_Thread


def sigint_handler(sig, frame) -> None:
    """Handler for SIGINT signal"""
    thread_safe_print("[INFO] Please use menu option to exit gracefully...")


def sigtstp_handler(sig, frame) -> None:
    """Handler for SIGTSTP signal"""
    if VIEW_TRAFFIC_THREAD:
        VIEW_TRAFFIC_THREAD.stop()


def show_menu_and_return_choice() -> str:
    thread_safe_print("\n1. Start / Stop IDS")
    thread_safe_print("2. View Live Traffic")
    thread_safe_print("3. View Intrusion Logs")
    thread_safe_print("4. Display Blocked IPs")
    thread_safe_print("5. Clear Blocked IP List")
    thread_safe_print("6. Unblock an IP")
    thread_safe_print("7. Exit")

    try:
        choice = int(input("\nEnter your choice: "))
        return CHOICES[choice]
    except ValueError:
        thread_safe_print("[ERROR] Invalid option selected. Try again...\n")
        return show_menu_and_return_choice()
    except KeyError:
        thread_safe_print("[ERROR] Invalid option selected. Try again...\n")
        return show_menu_and_return_choice()


def main() -> None:
    global IDS_THREAD, VIEW_TRAFFIC_THREAD, FIREWALL_UPDATE_THREAD, IP_SET_LOCK

    while True:
        choice = show_menu_and_return_choice()
        if choice == CHOICE_START_STOP_IDS:
            # start / stop ids service
            if IDS_THREAD is None:
                IDS_THREAD = IDS_Service()
                IDS_THREAD.start()
            else:
                IDS_THREAD.stop()
                IDS_THREAD.join()
                IDS_THREAD = None

        elif choice == CHOICE_VIEW_TRAFFIC:
            # show live traffic
            VIEW_TRAFFIC_THREAD = View_Traffic_Thread()
            VIEW_TRAFFIC_THREAD.start()
            VIEW_TRAFFIC_THREAD.join()
            VIEW_TRAFFIC_THREAD = None

        elif choice == CHOICE_VIEW_LOGS:
            # show logs from log file
            try:
                logs_df = pd.read_csv(LOG_FILE_NAME, sep="---", engine="python")
                thread_safe_print("\n[INFO] The following logs were found: \n")
            except FileNotFoundError:
                thread_safe_print(
                    "[ERROR] The log file does not exist. Run IDS service at least once to create it..."
                )
                continue
            except pd.errors.EmptyDataError:
                thread_safe_print("\n[WARN]The log file is empty.")
                continue

            logs_df["Timestamp"] = pd.to_datetime(
                logs_df["Date"] + " " + logs_df["Time"], format="%d-%m-%y %H:%M:%S"
            )

            last_entries = (
                logs_df.groupby(["Attacker IP", "Intrusion Type"])
                .agg(
                    {
                        "Timestamp": "max",
                        "Targeted Ports/Flags": lambda x: f"{x.min()} - {x.max()}",
                        "Time Span Of Attack": "max",
                    }
                )
                .reset_index()
            )

            last_entries["Date"] = logs_df["Timestamp"].dt.strftime("%d-%m-%y")
            last_entries["Time"] = logs_df["Timestamp"].dt.strftime("%H:%M:%S")
            last_entries = last_entries[LOGS_DF_ORDER].drop(columns=["Timestamp"])
            thread_safe_print(last_entries.to_markdown(index=False))

        elif choice == CHOICE_VIEW_BLOCKED_IPS:
            # show currently blocked ips
            thread_safe_print("\n[INFO] Currently blocked IPs are:")
            blocked_set = set()
            with IP_SET_LOCK:
                blocked_set = deepcopy(BLOCKED_IP_SET)

            for ip in blocked_set:
                thread_safe_print(f"\t{ip}")

        elif choice == CHOICE_CLEAR_BLOCKED_LIST:
            # clear current blocked list
            error_occurred = False

            blocked_set = set()

            with IP_SET_LOCK:
                blocked_set = deepcopy(BLOCKED_IP_SET)

            for ip in blocked_set:
                if not update_firewall_unblock_ip(ip):
                    thread_safe_print("\n[ERROR] Error in clearing blocked IP list")
                    error_occurred = True
                    break
            if not error_occurred and clear_blocked_ip_set():
                thread_safe_print("[INFO] The blocked IP list was cleared successfully")
            else:
                thread_safe_print("[ERROR] Error occurred")

        elif choice == CHOICE_UNBLOCK_IP:
            # unblock a particular ip
            unblocked_ip = input("Enter the IP that you want to unblock: ")
            if not is_valid_ip(unblocked_ip) or unblocked_ip not in BLOCKED_IP_SET:
                thread_safe_print("[ERROR] Invalid IP entered, try again...")
                continue

            if not update_firewall_unblock_ip(unblocked_ip) or not remove_ip_from_blocked_set(unblocked_ip):
                thread_safe_print("\n[ERROR] Unblocking the selected IP failed")

        else:
            # exit
            thread_safe_print("\n[INFO] Exiting...")
            # stop ids service, if running
            if IDS_THREAD is not None:
                IDS_THREAD.stop()
                IDS_THREAD.join()
                IDS_THREAD = None

            if FIREWALL_UPDATE_THREAD is not None:
                thread_safe_print("[INFO] Stopping IPtables update service...")
                FIREWALL_UPDATE_THREAD.join()
                FIREWALL_UPDATE_THREAD = None
            return 0


if __name__ == "__main__":
    # register signal handlers
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTSTP, sigtstp_handler)

    # begin main function
    main()
