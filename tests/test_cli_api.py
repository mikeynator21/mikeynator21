"""Tests for how the CLI classifies failures talking to the daemon.

Getting this wrong is not cosmetic: reporting "not running" about a daemon that
is running led `wifiguard allow` to write a rule locally and report success,
while the running daemon carried on blocking the name.
"""

import errno
import io
import sys
import unittest
import urllib.error
from unittest import mock

from wifiguard import cli
from wifiguard.config import Config


def _config():
    config = Config()
    config.dashboard.address = "127.0.0.1"
    config.dashboard.port = 8080
    return config


class ClassificationTests(unittest.TestCase):
    def _call(self, raised):
        with mock.patch.object(cli.urllib.request, "urlopen", side_effect=raised):
            return cli._api(_config(), "/api/status")

    def test_connection_refused_means_not_running(self):
        error = urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
        with self.assertRaises(cli.NotRunning):
            self._call(error)

    def test_host_unreachable_means_not_running(self):
        error = urllib.error.URLError(OSError(errno.EHOSTUNREACH, "unreachable"))
        with self.assertRaises(cli.NotRunning):
            self._call(error)

    def test_a_timeout_is_ambiguous_not_absent(self):
        """The request went out; whether it was applied is unknown."""
        with self.assertRaises(cli.Ambiguous):
            self._call(TimeoutError("timed out"))

    def test_a_dropped_connection_is_ambiguous(self):
        error = urllib.error.URLError(OSError(errno.ECONNRESET, "reset by peer"))
        with self.assertRaises(cli.Ambiguous):
            self._call(error)

    def test_401_is_an_auth_failure(self):
        error = urllib.error.HTTPError(
            "http://x/api", 401, "Unauthorized", {}, io.BytesIO(b'{"error":"nope"}')
        )
        with self.assertRaises(cli.ApiError) as ctx:
            self._call(error)
        self.assertIn("credentials", str(ctx.exception).lower() + " credentials")

    def test_429_is_an_auth_failure(self):
        error = urllib.error.HTTPError(
            "http://x/api", 429, "Too Many Requests", {}, io.BytesIO(b"{}")
        )
        with self.assertRaises(cli.ApiError):
            self._call(error)

    def test_403_is_not_reported_as_an_auth_problem(self):
        """Read-only mode returns 403 before credentials are looked at, so
        blaming the token sends people hunting for the wrong thing."""
        error = urllib.error.HTTPError(
            "http://x/api", 403, "Forbidden", {},
            io.BytesIO(b'{"error":"the dashboard is in read-only mode"}'),
        )
        with self.assertRaises(cli.ApiError) as ctx:
            self._call(error)
        message = str(ctx.exception)
        self.assertIn("read-only", message)
        self.assertNotIn("token", message)
        self.assertNotIn("sudo", message)

    def test_other_http_errors_report_themselves(self):
        error = urllib.error.HTTPError(
            "http://x/api", 500, "Server Error", {}, io.BytesIO(b"{}")
        )
        with self.assertRaises(cli.ApiError) as ctx:
            self._call(error)
        self.assertIn("500", str(ctx.exception))


class LocalRuleFallbackTests(unittest.TestCase):
    """`allow` and `block` must never claim a change they did not make."""

    def test_a_refusal_does_not_fall_back_to_writing_locally(self):
        with mock.patch.object(cli, "_api", side_effect=cli.ApiError("refused")), \
             mock.patch.object(cli, "Application") as application:
            code = cli._local_rule(_config(), "example.com", allow=True)
        self.assertEqual(code, 1)
        application.assert_not_called()

    def test_an_ambiguous_failure_does_not_fall_back_either(self):
        with mock.patch.object(cli, "_api", side_effect=cli.Ambiguous("timed out")), \
             mock.patch.object(cli, "Application") as application:
            code = cli._local_rule(_config(), "example.com", allow=True)
        self.assertEqual(code, 2)
        application.assert_not_called()

    def test_not_running_does_fall_back(self):
        with mock.patch.object(cli, "_api", side_effect=cli.NotRunning("refused")), \
             mock.patch.object(cli, "Application") as application:
            code = cli._local_rule(_config(), "example.com", allow=True)
        self.assertEqual(code, 0)
        application.return_value.add_local_rule.assert_called_once()

    def test_success_reports_success(self):
        with mock.patch.object(cli, "_api", return_value={}), \
             mock.patch.object(cli, "Application") as application:
            code = cli._local_rule(_config(), "example.com", allow=True)
        self.assertEqual(code, 0)
        application.assert_not_called()


class PortConflictMessageTests(unittest.TestCase):
    """The first thing most installs hit is something already on port 53."""

    def run_with(self, holder):
        from wifiguard import config as config_module

        error = io.StringIO()
        app = mock.Mock()
        app.start.side_effect = OSError("[Errno 98] Address already in use")
        args = mock.Mock(update=False, no_gateway=True, no_dashboard=True)
        with mock.patch.object(cli, "_port_holder", return_value=holder):
            with mock.patch.object(cli, "Application", return_value=app):
                with mock.patch.object(sys, "stderr", error):
                    code = cli.command_run(args, config_module.Config())
        return code, error.getvalue()

    def test_it_names_the_process_holding_the_port(self):
        code, text = self.run_with("dnsmasq (pid 4021)")
        self.assertEqual(code, 1)
        self.assertIn("dnsmasq (pid 4021)", text)

    def test_it_does_not_blame_systemd_resolved_for_another_program(self):
        _, text = self.run_with("dnsmasq (pid 4021)")
        self.assertNotIn("systemd-resolved", text)
        self.assertIn("server.port", text)

    def test_it_gives_the_fix_when_resolved_really_is_the_holder(self):
        _, text = self.run_with("systemd-resolve (pid 812)")
        self.assertIn("systemctl disable --now systemd-resolved", text)

    def test_it_still_guesses_when_the_holder_is_unknown(self):
        _, text = self.run_with("")
        self.assertIn("most Ubuntu and Debian", text)
        self.assertIn("systemctl disable --now systemd-resolved", text)

    def test_a_failure_building_the_application_is_a_sentence_not_a_traceback(self):
        from wifiguard import config as config_module

        error = io.StringIO()
        args = mock.Mock(update=False, no_gateway=True, no_dashboard=True)
        with mock.patch.object(cli, "Application", side_effect=OSError("disk is full")):
            with mock.patch.object(sys, "stderr", error):
                code = cli.command_run(args, config_module.Config())
        self.assertEqual(code, 1)
        self.assertIn("disk is full", error.getvalue())


class PortHolderTests(unittest.TestCase):
    """`ss` output is not something to show a person unedited."""

    def holder(self, line):
        result = mock.Mock(stdout="State Recv-Q Send-Q Local\n" + line)
        with mock.patch.object(cli.shutil, "which", return_value="/bin/ss"):
            with mock.patch("subprocess.run", return_value=result):
                return cli._port_holder(53)

    def test_program_and_pid_are_extracted(self):
        self.assertEqual(
            self.holder('udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* '
                        'users:(("systemd-resolve",pid=812,fd=12))'),
            "systemd-resolve (pid 812)",
        )

    def test_an_unfamiliar_shape_is_passed_through(self):
        self.assertEqual(self.holder('udp UNCONN 0 0 :::53 users:(("odd"))'), "odd")

    def test_no_holder_when_nothing_is_listening(self):
        self.assertEqual(self.holder("udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*"), "")

    def test_no_holder_without_ss(self):
        with mock.patch.object(cli.shutil, "which", return_value=None):
            self.assertEqual(cli._port_holder(53), "")


if __name__ == "__main__":
    unittest.main()
