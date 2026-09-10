"""Tests for the gateway: firewall rules, DHCP, clustering and networks."""

import ipaddress
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from wifiguard.cluster import Cluster, ClusterConfig, IdleMonitor, NodeState
from wifiguard.gateway import firewall, hotspot, networks, reflector
from wifiguard.gateway.dhcp import DHCPConfig, DHCPServer, parse_packet
from wifiguard.server import RateLimiter

SUBNET = ipaddress.ip_network("10.42.7.0/24")


def build_discover(mac=b"\xaa\xbb\xcc\xdd\xee\xff", hostname=b"phone", message_type=1,
                   requested=None, xid=b"\x12\x34\x56\x78"):
    packet = bytearray()
    packet += struct.pack("!BBBB", 1, 1, 6, 0)
    packet += xid
    packet += struct.pack("!HH", 0, 0x8000)
    packet += b"\x00" * 16
    packet += mac + b"\x00" * 10
    packet += b"\x00" * 192
    packet += b"\x63\x82\x53\x63"
    packet += bytes([53, 1, message_type])
    packet += bytes([12, len(hostname)]) + hostname
    if requested:
        packet += bytes([50, 4]) + socket.inet_aton(requested)
    packet += bytes([255])
    return bytes(packet)


class FirewallRuleTests(unittest.TestCase):
    def rules(self, **overrides):
        settings = dict(
            ap_interface="wlan1", uplink_interface="wlan0", subnet=SUBNET,
        )
        settings.update(overrides)
        return firewall.build_ruleset(firewall.GatewayRules(**settings))

    def test_dns_is_redirected(self):
        text = self.rules()
        self.assertIn("udp dport 53 redirect to :53", text)
        self.assertIn("tcp dport 53 redirect to :53", text)

    def test_masquerade_uses_the_uplink(self):
        self.assertIn('ip saddr 10.42.7.0/24 oifname "wlan0" masquerade', self.rules())

    def test_dot_and_doq_rejected(self):
        text = self.rules()
        for port in ("853", "784", "8853"):
            self.assertIn(f"dport {port} reject", text)

    def test_public_doh_addresses_rejected(self):
        text = self.rules()
        for address in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "94.140.14.14"):
            self.assertIn(address, text)

    def test_bypass_blocking_can_be_disabled(self):
        self.assertNotIn("dport 853 reject", self.rules(block_encrypted_dns_bypass=False))

    def test_ipv6_dropped_by_default(self):
        self.assertIn("no unfiltered IPv6 path", self.rules())

    def test_ipv6_forwarded_when_enabled(self):
        self.assertNotIn("no unfiltered IPv6 path", self.rules(allow_ipv6=True))

    def test_clients_isolated_from_the_joined_network(self):
        self.assertIn('iifname "wlan1" oifname "wlan0" drop', self.rules())

    def test_isolation_needs_the_uplink_subnet(self):
        # Without knowing the subnet there is nothing to isolate against, and
        # the setting silently does nothing -- which is worth asserting so the
        # caller is required to supply it.
        self.assertNotIn("ip daddr", self.rules().split("chain forward")[1].split("accept")[0])

    def test_isolation_drops_the_uplink_subnet(self):
        text = self.rules(uplink_subnet="192.168.1.0/24")
        self.assertIn('iifname "wlan1" ip daddr 192.168.1.0/24 drop', text)

    def test_isolation_precedes_the_accept_that_would_shadow_it(self):
        """Rule order is the whole point.

        nftables takes the first matching rule, so an isolation drop placed
        after the accept never runs. This asserts the ordering directly rather
        than just the presence of both rules.
        """
        forward = self.rules(uplink_subnet="192.168.1.0/24").split("chain forward")[1]
        drop_at = forward.index("ip daddr 192.168.1.0/24 drop")
        accept_at = forward.index('oifname "wlan0" ip version 4 accept')
        self.assertLess(drop_at, accept_at)

    def test_isolation_can_be_turned_off(self):
        text = self.rules(uplink_subnet="192.168.1.0/24", isolate_from_uplink=False)
        self.assertNotIn("ip daddr 192.168.1.0/24 drop", text)

    def test_isolation_still_allows_the_internet(self):
        # Only the uplink's own subnet is dropped; everything beyond it is
        # accepted out of the uplink interface.
        text = self.rules(uplink_subnet="192.168.1.0/24")
        self.assertIn('iifname "wlan1" oifname "wlan0" ip version 4 accept', text)

    def test_vpn_kill_switch_pins_the_tunnel(self):
        text = self.rules(vpn_interface="wg0")
        self.assertIn('oifname "wg0"', text)
        self.assertIn('ip saddr 10.42.7.0/24 oifname "wg0" masquerade', text)

    def test_forward_policy_is_drop(self):
        self.assertIn("type filter hook forward priority filter; policy drop;", self.rules())

    def test_resolver_not_exposed_to_the_joined_network(self):
        self.assertIn('iifname "wlan0" udp dport 53 drop', self.rules())


class RulesetSyntaxTests(unittest.TestCase):
    """Validate the ruleset with nft itself, not just by matching strings.

    Checking that the generated text contains the right substrings does not
    prove the kernel will accept it -- an invalid chain hook renders a ruleset
    that reads correctly and loads on nothing. `nft -c` parses and validates
    without applying, which catches that.
    """

    def setUp(self):
        if shutil.which("nft") is None:
            self.skipTest("nft is not installed")

    def _validate(self, text: str) -> None:
        result = subprocess.run(
            ["nft", "-c", "-f", "-"], input=text,
            capture_output=True, text=True, check=False, timeout=30,
        )
        if result.returncode != 0:
            message = result.stderr.strip()
            if "Operation not permitted" in message or "Permission denied" in message:
                self.skipTest("nft check mode needs privileges here")
            self.fail(f"nft rejected the generated ruleset:\n{message}")

    def test_ruleset_with_isolation_is_valid(self):
        self._validate(
            firewall.build_ruleset(
                firewall.GatewayRules(
                    ap_interface="wlan1", uplink_interface="wlan0", subnet=SUBNET,
                    uplink_subnet="192.168.1.0/24",
                )
            )
        )

    def test_default_ruleset_is_valid(self):
        self._validate(
            firewall.build_ruleset(
                firewall.GatewayRules(
                    ap_interface="wlan1", uplink_interface="wlan0", subnet=SUBNET
                )
            )
        )

    def test_ruleset_valid_with_vpn_killswitch(self):
        self._validate(
            firewall.build_ruleset(
                firewall.GatewayRules(
                    ap_interface="wlan1", uplink_interface="wlan0", subnet=SUBNET,
                    vpn_interface="wg0",
                )
            )
        )

    def test_ruleset_valid_with_ipv6_and_no_bypass_blocking(self):
        self._validate(
            firewall.build_ruleset(
                firewall.GatewayRules(
                    ap_interface="wlan1", uplink_interface="wlan0", subnet=SUBNET,
                    allow_ipv6=True, block_encrypted_dns_bypass=False,
                    extra_allowed_ports=[8443],
                )
            )
        )

    def test_nat_hooks_are_real_hooks(self):
        # srcnat and dstnat are priorities, not hooks; confusing the two
        # produces a ruleset the kernel refuses outright.
        text = firewall.build_ruleset(
            firewall.GatewayRules(
                ap_interface="wlan1", uplink_interface="wlan0", subnet=SUBNET
            )
        )
        self.assertIn("type nat hook prerouting priority dstnat", text)
        self.assertIn("type nat hook postrouting priority srcnat", text)
        self.assertNotIn("hook srcnat", text)
        self.assertNotIn("hook dstnat", text)


class SharedNetworkTests(unittest.TestCase):
    """Letting two client networks reach each other, for casting and printing."""

    def rules(self, **overrides):
        settings = dict(
            ap_interface="wlan1", uplink_interface="wlan0", subnet=SUBNET,
            uplink_subnet="192.168.1.0/24",
        )
        settings.update(overrides)
        return firewall.build_ruleset(firewall.GatewayRules(**settings))

    def test_no_sharing_by_default(self):
        self.assertNotIn("ip saddr {", self.rules().split("chain forward")[1])

    def test_sharing_accepts_between_the_named_networks(self):
        text = self.rules(shared_networks=["10.42.7.0/24", "10.60.0.0/24"])
        self.assertIn(
            "ip saddr { 10.42.7.0/24, 10.60.0.0/24 } "
            "ip daddr { 10.42.7.0/24, 10.60.0.0/24 } accept",
            text,
        )

    def test_a_single_network_shares_with_nothing(self):
        # Sharing needs two sides; one network on its own is a no-op.
        self.assertNotIn("ip saddr {", self.rules(shared_networks=["10.42.7.0/24"]).split("chain forward")[1])

    def test_sharing_does_not_override_uplink_isolation(self):
        """The joined network must stay off-limits even when sharing is on."""
        forward = self.rules(shared_networks=["10.42.7.0/24", "10.60.0.0/24"]).split("chain forward")[1]
        isolation_at = forward.index("ip daddr 192.168.1.0/24 drop")
        sharing_at = forward.index("ip saddr { 10.42.7.0/24")
        self.assertLess(isolation_at, sharing_at)

    def test_discovery_traffic_is_accepted_on_input(self):
        text = self.rules()
        self.assertIn("224.0.0.251", text)
        self.assertIn("239.255.255.250", text)

    def test_ruleset_with_sharing_is_valid(self):
        if shutil.which("nft") is None:
            self.skipTest("nft is not installed")
        result = subprocess.run(
            ["nft", "-c", "-f", "-"],
            input=self.rules(shared_networks=["10.42.7.0/24", "10.60.0.0/24"], allow_ipv6=True),
            capture_output=True, text=True, check=False, timeout=30,
        )
        if result.returncode != 0 and "not permitted" in result.stderr:
            self.skipTest("nft check mode needs privileges here")
        self.assertEqual(result.returncode, 0, result.stderr)


class ReflectorTests(unittest.TestCase):
    def test_default_groups_cover_the_common_protocols(self):
        names = {group.name for group in reflector.DEFAULT_GROUPS}
        self.assertEqual(names, {"mDNS", "SSDP"})

    def test_mdns_uses_the_required_ttl(self):
        # RFC 6762 requires 255, and receivers may reject anything lower.
        self.assertEqual(reflector.MDNS.ttl, 255)
        self.assertEqual(reflector.MDNS.address, "224.0.0.251")
        self.assertEqual(reflector.MDNS.port, 5353)

    def test_ssdp_group(self):
        self.assertEqual(reflector.SSDP.address, "239.255.255.250")
        self.assertEqual(reflector.SSDP.port, 1900)

    def test_groups_from_names(self):
        self.assertEqual(reflector.groups_from_names(["mdns"]), (reflector.MDNS,))
        self.assertEqual(reflector.groups_from_names([]), reflector.DEFAULT_GROUPS)

    def test_unknown_protocol_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            reflector.groups_from_names(["bonjour"])
        self.assertIn("bonjour", str(ctx.exception))

    def test_one_interface_is_not_started(self):
        instance = reflector.MulticastReflector(["wlan1"])
        instance.start()
        self.assertFalse(instance.running)

    def test_duplicate_interfaces_are_collapsed(self):
        instance = reflector.MulticastReflector(["wlan1", "wlan1", "eth0"])
        self.assertEqual(instance.interfaces, ["wlan1", "eth0"])

    def test_packets_from_ourselves_are_not_reflected(self):
        """This is what stops a reflection being reflected back for ever."""
        instance = reflector.MulticastReflector(
            ["a", "b"], own_addresses={"10.42.7.1", "10.60.0.1"}
        )
        instance._reflect(reflector.MDNS, "a", b"payload", "10.60.0.1")
        self.assertEqual(instance.stats.self_originated, 1)
        self.assertEqual(instance.stats.reflected, 0)

    def test_a_repeated_packet_is_only_reflected_once(self):
        instance = reflector.MulticastReflector(["a", "b"])
        self.assertFalse(instance._already_seen(reflector.MDNS, b"hello"))
        self.assertTrue(instance._already_seen(reflector.MDNS, b"hello"))

    def test_the_same_bytes_on_another_protocol_are_distinct(self):
        instance = reflector.MulticastReflector(["a", "b"])
        instance._already_seen(reflector.MDNS, b"hello")
        self.assertFalse(instance._already_seen(reflector.SSDP, b"hello"))

    def test_the_digest_cache_is_bounded(self):
        instance = reflector.MulticastReflector(["a", "b"])
        for index in range(5000):
            instance._already_seen(reflector.MDNS, str(index).encode())
        self.assertLessEqual(len(instance._seen), 4096)

    def test_status_reports_what_is_covered(self):
        status = reflector.MulticastReflector(["a", "b"]).status()
        self.assertFalse(status["running"])
        self.assertEqual(status["interfaces"], ["a", "b"])
        self.assertTrue(all(group["covers"] for group in status["groups"]))


class HotspotConfigTests(unittest.TestCase):
    def config(self, **overrides):
        settings = dict(
            interface="wlan1", ssid="WiFiGuard", passphrase="a-long-passphrase",
            subnet=SUBNET,
        )
        settings.update(overrides)
        return hotspot.build_hostapd_config(hotspot.HotspotConfig(**settings))

    def test_wpa3_transition_by_default(self):
        text = self.config()
        self.assertIn("wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE", text)
        self.assertIn("sae_require_mfp=1", text)

    def test_wpa3_only(self):
        text = self.config(wpa3_only=True)
        self.assertIn("wpa_key_mgmt=SAE", text)
        self.assertIn("ieee80211w=2", text)
        self.assertNotIn("wpa_passphrase=", text)

    def test_only_ccmp_ciphers(self):
        text = self.config()
        self.assertIn("rsn_pairwise=CCMP", text)
        self.assertNotIn("TKIP", text)

    def test_group_key_rotation(self):
        self.assertIn("wpa_group_rekey=", self.config())

    def test_five_ghz_band(self):
        text = self.config(band="5")
        self.assertIn("hw_mode=a", text)
        self.assertIn("ieee80211ac=1", text)

    def test_short_passphrase_rejected(self):
        with self.assertRaises(hotspot.HotspotError):
            self.config(passphrase="short")

    def test_long_ssid_rejected(self):
        with self.assertRaises(hotspot.HotspotError):
            self.config(ssid="x" * 33)


class DHCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.server = DHCPServer(
            DHCPConfig(
                interface="wlan1", subnet=SUBNET, server_ip="10.42.7.1",
                dns_servers=["10.42.7.1", "10.9.0.2"],
                lease_file=Path(self.tmp.name) / "leases.json",
            )
        )

    def test_discover_produces_an_offer(self):
        offer = self.server.handle_packet(build_discover())
        self.assertIsNotNone(offer)
        parsed = parse_packet(offer)
        self.assertEqual(parsed["options"][53][0], 2)  # OFFER

    def test_offered_address_is_in_range(self):
        offer = self.server.handle_packet(build_discover())
        address = ipaddress.ip_address(socket.inet_ntoa(offer[16:20]))
        self.assertIn(address, SUBNET)

    def test_dns_option_lists_every_node(self):
        offer = self.server.handle_packet(build_discover())
        option = parse_packet(offer)["options"][6]
        addresses = [socket.inet_ntoa(option[i:i + 4]) for i in range(0, len(option), 4)]
        self.assertEqual(addresses, ["10.42.7.1", "10.9.0.2"])

    def test_router_option_points_at_us(self):
        offer = self.server.handle_packet(build_discover())
        self.assertEqual(socket.inet_ntoa(parse_packet(offer)["options"][3]), "10.42.7.1")

    def test_request_acknowledged(self):
        self.server.handle_packet(build_discover())
        offered = self.server.leases["aa:bb:cc:dd:ee:ff"].ip
        ack = self.server.handle_packet(build_discover(message_type=3, requested=offered))
        self.assertEqual(parse_packet(ack)["options"][53][0], 5)  # ACK

    def test_same_device_keeps_its_address(self):
        first = self.server.handle_packet(build_discover())
        second = self.server.handle_packet(build_discover())
        self.assertEqual(first[16:20], second[16:20])

    def test_different_devices_get_different_addresses(self):
        first = self.server.handle_packet(build_discover(mac=b"\x01" * 6))
        second = self.server.handle_packet(build_discover(mac=b"\x02" * 6))
        self.assertNotEqual(first[16:20], second[16:20])

    def test_hostname_is_learned(self):
        self.server.handle_packet(build_discover(hostname=b"kitchen-tv"))
        self.assertEqual(self.server.leases["aa:bb:cc:dd:ee:ff"].hostname, "kitchen-tv")

    def test_leases_persist(self):
        self.server.handle_packet(build_discover(message_type=3))
        self.server._save_leases()
        reloaded = DHCPServer(self.server.config)
        self.assertIn("aa:bb:cc:dd:ee:ff", reloaded.leases)

    def test_garbage_is_ignored(self):
        self.assertIsNone(self.server.handle_packet(b"nonsense"))
        self.assertIsNone(parse_packet(b"\x00" * 100))


class ClusterTests(unittest.TestCase):
    def config(self, **overrides):
        settings = dict(
            enabled=True, name="laptop", address="10.9.0.1",
            peers=["10.9.0.2"], secret="s" * 64, priority=50,
        )
        settings.update(overrides)
        return ClusterConfig(**settings)

    def test_message_signing_round_trip(self):
        cluster = Cluster(self.config())
        envelope = cluster._sign({"type": "beat", "node": "laptop"})
        self.assertEqual(cluster._verify(envelope)["node"], "laptop")

    def test_tampered_message_rejected(self):
        cluster = Cluster(self.config())
        envelope = cluster._sign({"type": "beat", "node": "laptop"})
        envelope["body"] = envelope["body"].replace("laptop", "attacker")
        self.assertIsNone(cluster._verify(envelope))
        self.assertEqual(cluster.rejected, 1)

    def test_wrong_secret_rejected(self):
        envelope = Cluster(self.config(secret="a" * 64))._sign({"x": 1})
        self.assertIsNone(Cluster(self.config(secret="b" * 64))._verify(envelope))

    def test_higher_priority_node_is_first(self):
        cluster = Cluster(self.config(priority=50))
        cluster.nodes["phone"] = NodeState(
            name="phone", address="10.9.0.2", priority=90, effective_priority=90
        )
        self.assertEqual(cluster.resolver_order()[0], "10.9.0.2")
        self.assertFalse(cluster.is_preferred())

    def test_this_node_is_first_when_it_outranks(self):
        cluster = Cluster(self.config(priority=90))
        cluster.nodes["phone"] = NodeState(
            name="phone", address="10.9.0.2", priority=10, effective_priority=10
        )
        self.assertEqual(cluster.resolver_order()[0], "10.9.0.1")
        self.assertTrue(cluster.is_preferred())

    def test_dead_peers_are_dropped(self):
        cluster = Cluster(self.config())
        cluster.nodes["phone"] = NodeState(
            name="phone", address="10.9.0.2", effective_priority=99, last_seen=0
        )
        self.assertNotIn("10.9.0.2", cluster.resolver_order())

    def test_idle_node_yields(self):
        cluster = Cluster(self.config(priority=90, yield_when_idle=True, idle_after=0))
        cluster.idle.seconds_idle = lambda: 9999
        self.assertEqual(cluster.effective_priority(), 1)
        self.assertEqual(cluster.state, "yielding")

    def test_busy_node_does_not_yield(self):
        cluster = Cluster(self.config(priority=90, yield_when_idle=True, idle_after=300))
        cluster.idle.mark_busy()
        cluster.idle.seconds_idle = lambda: 1
        self.assertEqual(cluster.effective_priority(), 90)
        self.assertEqual(cluster.state, "active")

    def test_idle_laptop_hands_over_to_the_phone(self):
        # The whole point: the laptop outranks the phone while in use, and
        # steps aside when it is not.
        cluster = Cluster(self.config(priority=90, yield_when_idle=True, idle_after=300))
        cluster.nodes["phone"] = NodeState(
            name="phone", address="10.9.0.2", priority=50, effective_priority=50
        )
        cluster.idle.seconds_idle = lambda: 1
        self.assertEqual(cluster.resolver_order()[0], "10.9.0.1")

        cluster.idle.seconds_idle = lambda: 9999
        self.assertEqual(cluster.resolver_order()[0], "10.9.0.2")

    def test_secret_is_required(self):
        with self.assertRaises(ValueError):
            Cluster(self.config(secret="")).start()

    def test_shared_cache_entry_must_match_its_question(self):
        from wifiguard import dnsmsg
        from wifiguard.cache import CacheConfig, DNSCache
        import base64

        cache = DNSCache(CacheConfig())
        cluster = Cluster(self.config(), cache)
        query = dnsmsg.build_query("real.example", dnsmsg.TYPE_A)
        wire = dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "1.2.3.4", 300)

        # A peer claiming this answer belongs to a different name is refused.
        cluster._absorb_cache({
            "name": "victim.example", "qtype": 1, "qclass": 1,
            "wire": base64.b64encode(wire).decode(),
        })
        self.assertEqual(len(cache), 0)
        self.assertEqual(cluster.rejected, 1)

        cluster._absorb_cache({
            "name": "real.example", "qtype": 1, "qclass": 1,
            "wire": base64.b64encode(wire).decode(),
        })
        self.assertEqual(len(cache), 1)


class RateLimiterTests(unittest.TestCase):
    def test_burst_then_throttle(self):
        limiter = RateLimiter(rate=1, burst=5)
        self.assertTrue(all(limiter.allow("10.0.0.1") for _ in range(5)))
        self.assertFalse(limiter.allow("10.0.0.1"))

    def test_clients_are_independent(self):
        limiter = RateLimiter(rate=1, burst=2)
        limiter.allow("10.0.0.1")
        limiter.allow("10.0.0.1")
        self.assertFalse(limiter.allow("10.0.0.1"))
        self.assertTrue(limiter.allow("10.0.0.2"))

    def test_disabled_when_rate_is_zero(self):
        limiter = RateLimiter(rate=0, burst=0)
        self.assertTrue(all(limiter.allow("10.0.0.1") for _ in range(100)))


class NetworkDiscoveryTests(unittest.TestCase):
    def test_discovery_returns_a_list(self):
        self.assertIsInstance(networks.discover_local_networks(), list)

    def test_auto_always_includes_loopback(self):
        self.assertIn("127.0.0.1", networks.resolve_listen_addresses(["auto"]))

    def test_explicit_addresses_preserved(self):
        resolved = networks.resolve_listen_addresses(["192.168.1.5"])
        self.assertEqual(resolved, ["192.168.1.5"])

    def test_empty_falls_back_to_loopback(self):
        self.assertEqual(networks.resolve_listen_addresses([]), ["127.0.0.1"])

    def test_allowed_networks_never_shrink(self):
        configured = ["127.0.0.0/8", "10.0.0.0/8"]
        result = networks.allowed_networks(configured)
        for entry in configured:
            self.assertIn(entry, result)

    def test_summarise_returns_text(self):
        self.assertIsInstance(networks.summarise(), str)


if __name__ == "__main__":
    unittest.main()
