"""Tests for how the CLI classifies failures talking to the daemon.

Getting this wrong is not cosmetic: reporting "not running" about a daemon that
is running led `wifiguard allow` to write a rule locally and report success,
while the running daemon carried on blocking the name.
"""

import errno
import io
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


if __name__ == "__main__":
    unittest.main()
