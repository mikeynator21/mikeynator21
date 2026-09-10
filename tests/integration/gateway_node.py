"""Runs WiFiGuard as a gateway inside the testbed's gateway namespace.

This is `GatewayManager` with hostapd removed. Bringing up a real access point
needs a radio, which no sandbox has, so the client segment is a bridge with
veth links instead. Everything downstream of that is the shipping code:
the same nftables ruleset, the same DHCP server, the same resolver.
"""

from __future__ import annotations

import ipaddress
import logging
import signal
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from wifiguard import config as config_module  # noqa: E402
from wifiguard.app import Application  # noqa: E402
from wifiguard.gateway import firewall  # noqa: E402
from wifiguard.gateway.dhcp import DHCPConfig, DHCPServer  # noqa: E402

AP_INTERFACE = "ap0"
UPLINK_INTERFACE = "up0"
AP_SUBNET = ipaddress.ip_network("10.42.7.0/24")


def _uplink_subnet() -> str:
    """The subnet the uplink sits in, as the real gateway manager discovers it."""
    from wifiguard.gateway import networks

    for local in networks.discover_local_networks():
        if local.interface == UPLINK_INTERFACE:
            return str(local.network)
    return ""


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-20s %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("testbed.gateway")

    config_path = sys.argv[1]
    cfg = config_module.load(config_path)

    application = Application(cfg)

    # 1. Forwarding, which the test asserts is off beforehand.
    firewall.enable_forwarding()

    # 2. The real ruleset: NAT, DNS redirect, and the bypass blocking.
    rules = firewall.GatewayRules(
        ap_interface=AP_INTERFACE,
        uplink_interface=UPLINK_INTERFACE,
        subnet=AP_SUBNET,
        dns_port=cfg.server.port,
        dashboard_port=cfg.dashboard.port,
        isolate_from_uplink=cfg.hotspot.isolate_from_uplink,
        uplink_subnet=_uplink_subnet(),
    )
    firewall.apply_rules(rules)
    log.info("firewall applied")

    # 3. The resolver and dashboard.
    application.start(with_gateway=False, with_dashboard=True)

    # 4. The real DHCP server on the client segment.
    dhcp = DHCPServer(
        DHCPConfig(
            interface=AP_INTERFACE,
            subnet=AP_SUBNET,
            server_ip=str(next(AP_SUBNET.hosts())),
            dns_servers=[str(next(AP_SUBNET.hosts()))],
            lease_seconds=600,
            lease_file=cfg.lease_file,
        )
    )
    dhcp.start()

    # Feed DHCP-learned names and MACs to the policy engine, exactly as the
    # real gateway manager does.
    def publish() -> None:
        while not stopping.is_set():
            application._leases_changed(dhcp.active_leases())
            stopping.wait(2)

    stopping = threading.Event()
    threading.Thread(target=publish, daemon=True).start()

    def shutdown(signum, _frame):
        log.info("stopping")
        stopping.set()
        dhcp.stop()
        application.stop()
        firewall.teardown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print("GATEWAY READY", flush=True)
    signal.pause()
    return 0


if __name__ == "__main__":
    sys.exit(main())
