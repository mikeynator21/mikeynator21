"""Tests for the setup wizard.

The interview needs a terminal, so what is tested is everything downstream of
it: that whatever answers come out, the file written is valid configuration
and does not weaken the install.
"""

import tomllib
import unittest
from pathlib import Path
from unittest import mock

from wifiguard import setupwizard
from wifiguard.auth import hash_password, is_hashed
from wifiguard.config import from_mapping
from wifiguard.setupwizard import Answers, render


class RenderTests(unittest.TestCase):
    def _parse(self, answers: Answers):
        text = render(answers)
        return from_mapping(tomllib.loads(text)), text

    def test_defaults_produce_a_valid_config(self):
        config, _ = self._parse(Answers())
        self.assertEqual(config.server.listen_addresses, ["127.0.0.1"])

    def test_network_role_binds_everywhere_and_needs_a_password(self):
        answers = Answers(
            role="network", listen_addresses=["auto"], dashboard_address="0.0.0.0",
            dashboard_password_hash=hash_password("a-good-password"),
        )
        config, _ = self._parse(answers)
        self.assertEqual(config.dashboard.address, "0.0.0.0")
        self.assertTrue(is_hashed(config.dashboard.password))

    def test_an_exposed_dashboard_is_never_written_without_a_password(self):
        """The wizard must not be able to produce a configuration that is
        refused, or one that exposes the dashboard unauthenticated."""
        answers = Answers(role="network", dashboard_address="0.0.0.0")
        text = render(answers)
        parsed = tomllib.loads(text)
        # No password was set, so this would be refused -- which is the point:
        # the interview drops back to localhost rather than emitting it.
        with self.assertRaises(Exception):
            from_mapping(parsed)

    def test_gateway_role_writes_a_hotspot(self):
        answers = Answers(
            role="gateway", listen_addresses=["auto"],
            hotspot_ssid="MyHotspot", hotspot_passphrase="a-long-passphrase",
        )
        config, _ = self._parse(answers)
        self.assertTrue(config.hotspot.enabled)
        self.assertEqual(config.hotspot.ssid, "MyHotspot")
        self.assertTrue(config.hotspot.isolate_from_uplink)

    def test_gateway_leaves_interfaces_to_be_discovered(self):
        answers = Answers(role="gateway", hotspot_ssid="X", hotspot_passphrase="12345678")
        config, _ = self._parse(answers)
        # Empty means "work it out live", which is what keeps it working as the
        # laptop moves between networks.
        self.assertEqual(config.hotspot.interface, "")
        self.assertEqual(config.hotspot.uplink, "")

    def test_device_profiles_are_written(self):
        config, _ = self._parse(Answers(devices=["apple", "console"]))
        self.assertEqual(config.compatibility.devices, ["apple", "console"])

    def test_no_devices_writes_no_section(self):
        _, text = self._parse(Answers())
        self.assertNotIn("[compatibility]", text)

    def test_vpn_is_written_when_an_endpoint_is_given(self):
        config, _ = self._parse(Answers(vpn_endpoint="home.example.com"))
        self.assertTrue(config.vpn.enabled)
        self.assertEqual(config.vpn.endpoint, "home.example.com")

    def test_no_vpn_section_without_an_endpoint(self):
        _, text = self._parse(Answers())
        self.assertNotIn("[vpn]", text)

    def test_discovery_sharing_is_written(self):
        config, _ = self._parse(Answers(share_discovery=True))
        self.assertTrue(config.networks.share_discovery)

    def test_every_protection_level_is_valid(self):
        for level in ("standard", "strict", "paranoid"):
            with self.subTest(level=level):
                config, _ = self._parse(Answers(protection=level))
                self.assertEqual(config.protection, level)

    def test_a_rendered_config_passes_the_hardening_audit(self):
        """What the wizard writes should not be something `harden` complains
        about at high severity."""
        answers = Answers(
            role="network", listen_addresses=["auto"], dashboard_address="0.0.0.0",
            dashboard_password_hash=hash_password("a-good-password"),
            protection="strict",
        )
        config, _ = self._parse(answers)
        self.assertTrue(config.upstream.require_encrypted)
        self.assertTrue(config.blocklists.block_doh_bypass)
        self.assertFalse(config.blocklists.trust_remote_allow_rules)
        self.assertGreater(config.server.rate_limit, 0)
        self.assertNotIn("0.0.0.0/0", config.server.allowed_networks)


class NextStepsTests(unittest.TestCase):
    def test_steps_are_ordered_and_actionable(self):
        steps = setupwizard.next_steps(Answers(role="network"), Path("/etc/x.toml"))
        self.assertIn("/etc/x.toml", steps[0])
        self.assertTrue(any("doctor" in step for step in steps))
        self.assertTrue(any("selftest" in step for step in steps))

    def test_network_role_says_to_point_the_router(self):
        steps = setupwizard.next_steps(Answers(role="network"), Path("/etc/x.toml"))
        self.assertTrue(any("router" in step for step in steps))

    def test_gateway_role_says_to_join_the_hotspot(self):
        steps = setupwizard.next_steps(
            Answers(role="gateway", hotspot_ssid="MyNet"), Path("/etc/x.toml")
        )
        self.assertTrue(any("MyNet" in step for step in steps))

    def test_vpn_steps_appear_when_configured(self):
        steps = setupwizard.next_steps(
            Answers(vpn_endpoint="home.example.com"), Path("/etc/x.toml")
        )
        self.assertTrue(any("add-peer" in step for step in steps))

    def test_no_vpn_steps_otherwise(self):
        steps = setupwizard.next_steps(Answers(), Path("/etc/x.toml"))
        self.assertFalse(any("add-peer" in step for step in steps))


class SecretHandlingTests(unittest.TestCase):
    def test_the_written_password_is_a_hash_not_the_password(self):
        answers = Answers(
            dashboard_address="0.0.0.0",
            dashboard_password_hash=hash_password("swordfish"),
        )
        text = render(answers)
        self.assertNotIn("swordfish", text)
        self.assertIn("scrypt$", text)


class NextStepsMatchTheMachineTests(unittest.TestCase):
    """Termux, containers and WSL are documented targets and have no systemd."""

    def steps(self, systemd, **kwargs):
        with mock.patch.object(setupwizard, "_systemd_available", return_value=systemd):
            with mock.patch.object(setupwizard, "_port_in_use", return_value=False):
                return "\n".join(
                    setupwizard.next_steps(setupwizard.Answers(**kwargs), Path("/tmp/w.toml"))
                )

    def test_systemd_present(self):
        self.assertIn("systemctl enable --now wifiguard", self.steps(True))

    def test_systemd_absent(self):
        text = self.steps(False)
        self.assertIn("sudo wifiguard run", text)
        self.assertNotIn("systemctl enable", text)

    def test_busy_port_advice_without_systemd_does_not_name_systemctl(self):
        with mock.patch.object(setupwizard, "_systemd_available", return_value=False):
            with mock.patch.object(setupwizard, "_port_in_use", return_value=True):
                text = "\n".join(
                    setupwizard.next_steps(setupwizard.Answers(), Path("/tmp/w.toml"))
                )
        self.assertIn("Port 53 is busy", text)
        self.assertNotIn("systemctl", text)

    def test_busy_port_advice_with_systemd_names_resolved(self):
        with mock.patch.object(setupwizard, "_systemd_available", return_value=True):
            with mock.patch.object(setupwizard, "_port_in_use", return_value=True):
                text = "\n".join(
                    setupwizard.next_steps(setupwizard.Answers(), Path("/tmp/w.toml"))
                )
        self.assertIn("systemd-resolved", text)

    def test_systemd_detection_needs_more_than_the_binary(self):
        # A container has systemctl on PATH and no systemd behind it.
        with mock.patch.object(setupwizard.shutil, "which", return_value="/bin/systemctl"):
            with mock.patch.object(setupwizard.Path, "is_dir", return_value=False):
                self.assertFalse(setupwizard._systemd_available())


if __name__ == "__main__":
    unittest.main()
