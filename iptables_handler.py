import threading

from iptc import Table, Chain, Rule, Target
from utils import thread_safe_print


class IPtablesHandler(threading.Thread):
    """
    Thread class to manage IPtables interaction
    """

    def __init__(self, ip: str):
        super().__init__()
        self.ip = ip

    def run(self):
        table = Table(Table.FILTER)
        chain = Chain(table, "INPUT")
        rule = Rule()
        rule.src = self.ip
        rule.target = Target(rule, "DROP")

        chain.insert_rule(rule)
        thread_safe_print(f"[INFO] Blocking IP {self.ip}")


def update_firewall_unblock_ip(unblock_ip: str):
    """
    Update the firewall by unblocking an IP address
    """
    table = Table(Table.FILTER)
    chain = Chain(table, "INPUT")

    try:
        for rule in chain.rules:
            if unblock_ip and rule.src.split("/")[0] == unblock_ip:
                chain.delete_rule(rule)
                thread_safe_print(f"[INFO] IP {unblock_ip} was unblocked successfully")
    except Exception as err:
        thread_safe_print(f"[ERROR] {repr(err)}")
        return False
    return True
