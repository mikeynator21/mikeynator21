"""Password handling for the dashboard.

The dashboard can add VPN peers and switch filtering off, so reaching it is
close to owning the network it protects. Two things follow from that: it must
not be reachable from the network without a password, and the password must not
sit in a config file in the clear.

Hashing uses scrypt from the standard library, which is memory-hard -- a
stolen hash cannot be attacked at GPU speed the way a plain SHA-256 can.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

#: scrypt parameters. n=16384 costs roughly 16MB and a few tens of
#: milliseconds, which is nothing per login and a great deal per guess.
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32

PREFIX = "scrypt$"


def hash_password(password: str) -> str:
    """Hash a password for storage in the config file."""
    if not password:
        raise ValueError("a password is required")
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES,
    )
    return f"{PREFIX}{salt.hex()}${derived.hex()}"


def is_hashed(stored: str) -> bool:
    return stored.startswith(PREFIX) and stored.count("$") == 2


def verify_password(supplied: str, stored: str) -> bool:
    """Check a password against a stored value, hashed or not.

    A plaintext value in the config still works, so an existing install does
    not break on upgrade -- but it is compared in constant time all the same,
    and the caller warns about it.
    """
    if not stored:
        return False

    if not is_hashed(stored):
        return hmac.compare_digest(supplied, stored)

    try:
        _, salt_hex, expected_hex = stored.split("$", 2)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except (ValueError, TypeError):
        return False

    derived = hashlib.scrypt(
        supplied.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=len(expected) or KEY_BYTES,
    )
    return hmac.compare_digest(derived, expected)


class AttemptLimiter:
    """Slows down password guessing, per client address.

    scrypt already makes each guess expensive; this stops a client tying up
    the server making them, and turns a distributed guessing attempt into a
    visible one.
    """

    def __init__(self, limit: int = 5, window: float = 300.0, lockout: float = 300.0) -> None:
        self.limit = limit
        self.window = window
        self.lockout = lockout
        self._failures: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._lock = threading.Lock()

    def locked_out(self, client: str) -> float:
        """Seconds remaining on a lockout, or 0 if the client may try."""
        now = time.monotonic()
        with self._lock:
            until = self._locked.get(client)
            if until is None:
                return 0.0
            if now >= until:
                del self._locked[client]
                self._failures.pop(client, None)
                return 0.0
            return until - now

    def record_failure(self, client: str) -> bool:
        """Note a failed attempt. Returns True if the client is now locked out."""
        now = time.monotonic()
        with self._lock:
            attempts = [t for t in self._failures.get(client, []) if now - t < self.window]
            attempts.append(now)
            self._failures[client] = attempts

            if len(attempts) >= self.limit:
                self._locked[client] = now + self.lockout
                return True

            # Keep the map from growing without bound under a scan of many
            # source addresses.
            if len(self._failures) > 1024:
                self._failures = {
                    key: times for key, times in self._failures.items()
                    if times and now - times[-1] < self.window
                }
            return False

    def record_success(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)
            self._locked.pop(client, None)

    def status(self) -> dict[str, int]:
        with self._lock:
            return {
                "clients_with_failures": len(self._failures),
                "locked_out": len(self._locked),
            }


class AdminToken:
    """A secret shared between the daemon and the CLI on the same machine.

    Hashing the dashboard password is right for a human typing it, and wrong
    for the CLI: it has only the hash, and a hash is not a password. Rather
    than weaken the hashing or make `wifiguard status` prompt, the daemon
    writes a token that anyone who could already read the config can read --
    which is the same trust boundary, expressed honestly.
    """

    FILENAME = "admin.token"

    def __init__(self, state_dir) -> None:
        from pathlib import Path

        self.path = Path(state_dir) / self.FILENAME
        #: Held once the daemon has loaded it. Comparing against this rather
        #: than re-reading the file means tampering with the file does not
        #: grant access -- it only breaks the CLI until the next restart.
        self._value = ""

    def load_or_create(self) -> str:
        """Read the token, creating one if this is the first start."""
        import os
        import stat

        existing = self.read()
        if existing:
            self._value = existing
            return existing

        token = secrets.token_urlsafe(32)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Written before the mode is set, so create it closed rather than
        # widening it afterwards.
        handle = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(handle, "w", encoding="ascii") as file:
            file.write(token)
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        self._value = token
        return token

    def read(self) -> str:
        try:
            token = self.path.read_text(encoding="ascii").strip()
        except OSError:
            return ""
        return token if len(token) >= 20 else ""

    def matches(self, supplied: str) -> bool:
        """Compare against the token held in memory since start-up.

        Deliberately not a fresh read: otherwise anyone able to write the file
        could choose the secret, and "can write this file" is a weaker
        condition than "was here when the service started".
        """
        return bool(self._value) and hmac.compare_digest(supplied, self._value)


def looks_local(address: str) -> bool:
    """Whether an address means "this machine only"."""
    return address in ("127.0.0.1", "::1", "localhost", "")
