"""One command that gets WiFiGuard configured correctly.

The failure mode this exists to prevent is a half-configured install: the
resolver bound to the wrong address, the dashboard exposed without a password,
the VPN half set up. Each of those is a footgun, and each is avoidable by
asking three or four questions and writing the file properly.

Everything it decides is printed, so it is auditable rather than magic, and it
never overwrites an existing config without being told to.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import auth
from .compat import DEVICE_PROFILES

DEFAULT_CONFIG_PATH = Path("/etc/wifiguard/wifiguard.toml")


@dataclass
class Answers:
    role: str = "host"            # "network", "gateway" or "host"
    listen_addresses: list[str] = field(default_factory=lambda: ["127.0.0.1"])
    dashboard_address: str = "127.0.0.1"
    dashboard_password_hash: str = ""
    protection: str = "strict"
    devices: list[str] = field(default_factory=list)
    hotspot_ssid: str = ""
    hotspot_passphrase: str = ""
    vpn_endpoint: str = ""
    share_discovery: bool = False


def _ask(prompt: str, options: list[tuple[str, str, str]], default: str) -> str:
    """Ask a multiple-choice question. Returns the chosen key."""
    print(f"\n{prompt}")
    for index, (key, title, why) in enumerate(options, 1):
        marker = " (default)" if key == default else ""
        print(f"  {index}. {title}{marker}")
        if why:
            print(f"     {why}")
    while True:
        try:
            raw = input(f"\n  choose 1-{len(options)} [{default}]: ").strip()
        except EOFError:
            return default
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        for key, _, _ in options:
            if raw.lower() == key:
                return key
        print("  not one of the options.")


def _confirm(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    try:
        raw = input(f"  {prompt} [{suffix}]: ").strip().lower()
    except EOFError:
        return default
    if not raw:
        return default
    return raw in ("y", "yes")


def _prompt(prompt: str, default: str = "") -> str:
    try:
        raw = input(f"  {prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    except EOFError:
        return default
    return raw or default


def _secret(prompt: str) -> str:
    import getpass

    while True:
        first = getpass.getpass(f"  {prompt}: ")
        if not first:
            return ""
        if len(first) < 8:
            print("  at least 8 characters, please.")
            continue
        again = getpass.getpass("  again: ")
        if first != again:
            print("  those did not match.")
            continue
        return first


def _local_addresses() -> list[str]:
    from .gateway.networks import discover_local_networks

    return [local.address for local in discover_local_networks()]


def interview() -> Answers:
    """Ask the questions. Falls back to safe defaults with no terminal."""
    answers = Answers()

    role = _ask(
        "What do you want WiFiGuard to do?",
        [
            ("network", "Protect every device on my network",
             "Runs here and serves DNS to the whole LAN. You point your router's "
             "DHCP at this machine afterwards."),
            ("gateway", "Turn this laptop into a portable filtering router",
             "Joins any network and re-shares it as its own WiFi. Needs a second "
             "wireless adapter."),
            ("host", "Just protect this machine",
             "Binds to localhost only. Nothing else on the network is affected."),
        ],
        default="network",
    )
    answers.role = role

    if role == "network":
        addresses = _local_addresses()
        if addresses:
            print(f"\n  Found local addresses: {', '.join(addresses)}")
            print("  Binding all of them, so devices on any of your networks can reach it.")
        answers.listen_addresses = ["auto"]
        answers.dashboard_address = "0.0.0.0"
    elif role == "gateway":
        answers.listen_addresses = ["auto"]
        answers.dashboard_address = "127.0.0.1"
        print("\n  The hotspot other devices will join:")
        answers.hotspot_ssid = _prompt("network name (SSID)", "WiFiGuard")
        while not answers.hotspot_passphrase:
            answers.hotspot_passphrase = _secret("passphrase (8+ characters)")
            if not answers.hotspot_passphrase:
                print("  A passphrase is required -- an open hotspot lets anyone nearby use it.")
    else:
        answers.listen_addresses = ["127.0.0.1"]
        answers.dashboard_address = "127.0.0.1"

    # The dashboard is only worth a password when it is reachable.
    if answers.dashboard_address != "127.0.0.1":
        print("\n  The dashboard will be reachable from your network, so it needs a")
        print("  password -- anyone who reaches it could switch filtering off.")
        password = _secret("dashboard password (8+ characters)")
        if password:
            answers.dashboard_password_hash = auth.hash_password(password)
        else:
            print("  No password set, so the dashboard stays on localhost only.")
            answers.dashboard_address = "127.0.0.1"

    answers.protection = _ask(
        "How much filtering?",
        [
            ("strict", "Ads, trackers, malware and phishing",
             "The usual choice. Adds security lists on top of ad blocking."),
            ("standard", "Ads and trackers", "Lighter, fewer lists to fetch."),
            ("paranoid", "Everything, and require TLS 1.3 upstream",
             "Also trims log retention to a day."),
        ],
        default="strict",
    )

    print("\n  Which of these are on your network? Blank for none, 'all' for everything.")
    for profile in DEVICE_PROFILES:
        print(f"    {profile.key:<16} {profile.title}")
    print("\n  Each adds the minimum that class of device needs to work -- not its")
    print("  telemetry, which stays blocked.")
    raw = _prompt("devices (comma separated)", "")
    if raw:
        keys = {key.strip().lower() for key in raw.replace(" ", ",").split(",") if key.strip()}
        known = {profile.key for profile in DEVICE_PROFILES} | {"all"}
        answers.devices = sorted(keys & known)
        unknown = sorted(keys - known)
        if unknown:
            print(f"  Ignoring unrecognised: {', '.join(unknown)}")

    print()
    if _confirm("Set up the VPN, so your phone stays filtered away from home?", False):
        print("\n  Peers need an address to dial from outside: a static IP, or a")
        print("  dynamic-DNS name. You will also need UDP 51820 forwarded to this")
        print("  machine on your router.")
        answers.vpn_endpoint = _prompt("address peers dial", "")

    if role in ("network", "gateway"):
        print()
        answers.share_discovery = _confirm(
            "Let devices on different networks cast and print to each other?", False
        )

    return answers


def render(answers: Answers) -> str:
    """Turn the answers into a configuration file."""
    lines = [
        "# WiFiGuard configuration, written by `wifiguard setup`.",
        "# Every value here has a comment explaining it in `wifiguard init-config`.",
        "",
        f'protection = "{answers.protection}"',
        "",
        "[server]",
        "listen_addresses = ["
        + ", ".join(f'"{address}"' for address in answers.listen_addresses)
        + "]",
        "port = 53",
        "",
    ]

    if answers.devices:
        lines += [
            "[compatibility]",
            "# The minimum each class of device needs in order to work.",
            "devices = [" + ", ".join(f'"{key}"' for key in answers.devices) + "]",
            "",
        ]

    lines += ["[dashboard]", f'address = "{answers.dashboard_address}"', "port = 8080"]
    if answers.dashboard_password_hash:
        lines.append(f'password = "{answers.dashboard_password_hash}"')
    lines.append("")

    if answers.role == "gateway":
        lines += [
            "[hotspot]",
            "enabled = true",
            f'ssid = "{answers.hotspot_ssid}"',
            f'passphrase = "{answers.hotspot_passphrase}"',
            '# Left empty so they are worked out live, and keep working as you',
            '# move between networks.',
            'interface = ""',
            'uplink = ""',
            'subnet = ""',
            "isolate_from_uplink = true",
            "",
        ]

    if answers.share_discovery:
        lines += [
            "[networks]",
            "# Reflect mDNS and SSDP between local networks, so casting and",
            "# printing work across them.",
            "share_discovery = true",
            "",
        ]

    if answers.vpn_endpoint:
        lines += [
            "[vpn]",
            "enabled = true",
            f'endpoint = "{answers.vpn_endpoint}"',
            'subnet = "10.9.0.0/24"',
            "listen_port = 51820",
            "",
        ]

    return "\n".join(lines)


def next_steps(answers: Answers, path: Path) -> list[str]:
    """What the person has to do now, in order."""
    steps = [f"Config written to {path}."]

    if _port_in_use(53):
        steps.append(
            "Port 53 is busy -- usually systemd-resolved. Free it first:\n"
            "       sudo systemctl disable --now systemd-resolved\n"
            "       sudo rm -f /etc/resolv.conf\n"
            "       echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf"
        )

    steps.append("Check the machine is ready:  sudo wifiguard doctor")
    steps.append("Start it:                    sudo systemctl enable --now wifiguard")

    if answers.role == "network":
        steps.append(
            "Point your router's DHCP 'DNS server' setting at this machine.\n"
            "       Every device picks it up on its next lease -- nothing to install\n"
            "       on any of them."
        )
    elif answers.role == "gateway":
        steps.append(
            f"Join the '{answers.hotspot_ssid}' network from your other devices."
        )

    if answers.vpn_endpoint:
        steps.append(
            "Set up the tunnel and add your phone:\n"
            f"       sudo wifiguard vpn init --endpoint {answers.vpn_endpoint}\n"
            "       sudo wifiguard vpn add-peer phone --profile dns-only --mobile\n"
            "       (scan the QR code it prints, in the WireGuard app)"
        )

    steps.append("Confirm it works:            wifiguard selftest")
    return steps


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def run(path: Path | None = None, force: bool = False) -> int:
    target = path or DEFAULT_CONFIG_PATH

    print("WiFiGuard setup")
    print("=" * 60)
    print("A few questions, then a working configuration. Nothing is changed")
    print("on this machine until you start the service.")

    if target.exists() and not force:
        print(f"\n  {target} already exists.")
        if not sys.stdin.isatty() or not _confirm("Replace it?", False):
            print("  Left alone. Pass --force to overwrite.")
            return 1

    if not sys.stdin.isatty():
        print("\n  No terminal attached, so using safe defaults: filtering for this")
        print("  machine only, dashboard on localhost. Re-run interactively to")
        print("  configure more.")
        answers = Answers()
    else:
        answers = interview()

    contents = render(answers)

    print("\n" + "=" * 60)
    print("This is the configuration:\n")
    for line in contents.splitlines():
        # Never print the hash or the hotspot passphrase back to the terminal.
        if line.startswith(("password =", "passphrase =")):
            key = line.split("=", 1)[0].strip()
            print(f"  {key} = <set, not shown>")
        else:
            print(f"  {line}")
    print("=" * 60)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
        os.chmod(target, 0o600)
    except OSError as exc:
        print(f"\nCould not write {target}: {exc}", file=sys.stderr)
        if os.geteuid() != 0:
            print("Try again with sudo.", file=sys.stderr)
        return 1

    print("\nNext:\n")
    for index, step in enumerate(next_steps(answers, target), 1):
        print(f"  {index}. {step}")
    print()
    return 0
