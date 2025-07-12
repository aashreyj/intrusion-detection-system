import ipaddress
import threading

IS_LOCALHOST = False

CHOICE_START_STOP_IDS = "START_STOP_IDS"
CHOICE_VIEW_TRAFFIC = "VIEW_TRAFFIC"
CHOICE_VIEW_LOGS = "VIEW_LOGS"
CHOICE_VIEW_BLOCKED_IPS = "VIEW_BLOCKED_IPS"
CHOICE_CLEAR_BLOCKED_LIST = "CLEAR_BLOCKED_LIST"
CHOICE_UNBLOCK_IP = "UNBLOCK_IP"
CHOICE_EXIT = "EXIT"

CHOICES = {
    1: CHOICE_START_STOP_IDS,
    2: CHOICE_VIEW_TRAFFIC,
    3: CHOICE_VIEW_LOGS,
    4: CHOICE_VIEW_BLOCKED_IPS,
    5: CHOICE_CLEAR_BLOCKED_LIST,
    6: CHOICE_UNBLOCK_IP,
    7: CHOICE_EXIT,
}

LOG_FILE_NAME = "ids.log"
LOGS_DF_ORDER = [
    "Timestamp",
    "Date",
    "Time",
    "Intrusion Type",
    "Attacker IP",
    "Targeted Ports/Flags",
    "Time Span Of Attack",
]

IP_SET_LOCK = threading.Lock()
STDOUT_LOCK = threading.Lock()

BLOCKED_IP_SET = set()

IDS_THREAD = None
VIEW_TRAFFIC_THREAD = None
FIREWALL_UPDATE_THREAD = None


def thread_safe_print(message: str) -> None:
    """Print a message in a thread-safe manner"""
    with STDOUT_LOCK:
        print(message)


def is_valid_ip(ip_str: str) -> bool:
    """Validate if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError as err:
        thread_safe_print(f"[ERROR] {repr(err)}")
        return False


def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is already blocked"""
    with IP_SET_LOCK:
        res = ip in BLOCKED_IP_SET
    return res


def add_to_blocked_ip_set(ip: str) -> bool:
    """Add an IP address to the blocked set in a thread-safe manner"""
    if not is_valid_ip(ip):
        return False

    with IP_SET_LOCK:
        try:
            BLOCKED_IP_SET.add(ip)
        except Exception as err:
            thread_safe_print(f"[ERROR] {repr(err)}")
            return False
    return True


def remove_ip_from_blocked_set(ip: str) -> bool:
    """Remove an IP from the blocked set in a thread-safe manner"""
    with IP_SET_LOCK:
        try:
            BLOCKED_IP_SET.remove(ip)
        except Exception as err:
            thread_safe_print(f"[ERROR] {repr(err)}")
            return False
    return True


def clear_blocked_ip_set() -> bool:
    """Clear the blocked set"""
    with IP_SET_LOCK:
        try:
            BLOCKED_IP_SET.clear()
        except Exception as err:
            thread_safe_print(f"[ERROR] {repr(err)}")
            return False
    return True


def write_to_log_file(line: str) -> None:
    """Write a line to the log file"""
    with open(LOG_FILE_NAME, "a") as fp:
        fp.write(line)
