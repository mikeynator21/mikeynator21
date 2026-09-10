"""Test suite for WiFiGuard.

Logging is silenced here: several tests deliberately exercise failure paths
(unreachable upstreams, corrupt cache files, invalid rules) whose warnings would
otherwise bury the test results.
"""

import logging

logging.disable(logging.CRITICAL)
