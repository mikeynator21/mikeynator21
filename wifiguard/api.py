"""The dashboard and its JSON API.

A single-file HTTP server on the standard library. The dashboard is the honest
answer to "is this thing working, and why did it break that site?" -- so the
query log, the block reason for any name, and the per-source rule counts are all
one click away.

The API binds to localhost by default. Exposing it to the hotspot is a
deliberate choice, and setting a password is required before any write is
accepted from off-host.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import mimetypes
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

from .vpn import qr
from .vpn.wireguard import WireGuardError

if TYPE_CHECKING:  # pragma: no cover
    from .app import Application

log = logging.getLogger(__name__)

WEB_ROOT = Path(__file__).parent / "web"
MAX_BODY = 256 * 1024


class Dashboard:
    """Runs the HTTP server for one application instance."""

    def __init__(self, application: "Application") -> None:
        self.app = application
        self.config = application.config.dashboard
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        handler = _make_handler(self)
        try:
            self._server = ThreadingHTTPServer((self.config.address, self.config.port), handler)
        except OSError as exc:
            raise OSError(
                f"could not bind the dashboard to {self.config.address}:{self.config.port}: {exc}"
            ) from exc
        self._server.daemon_threads = True

        self._thread = threading.Thread(
            target=self._server.serve_forever, name="dashboard", daemon=True
        )
        self._thread.start()

        if self.config.address not in ("127.0.0.1", "::1", "localhost") and not self.config.password:
            log.warning(
                "the dashboard is reachable from the network at %s:%d with no password set. "
                "Set dashboard.password, or bind it to 127.0.0.1.",
                self.config.address,
                self.config.port,
            )
        log.info("dashboard on http://%s:%d", self.config.address, self.config.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- authentication ---------------------------------------------------

    def authorised(self, header: str | None) -> bool:
        if not self.config.password:
            return True
        if not header:
            return False
        try:
            scheme, _, value = header.partition(" ")
            if scheme.lower() == "basic":
                decoded = base64.b64decode(value).decode("utf-8")
                _, _, supplied = decoded.partition(":")
            elif scheme.lower() == "bearer":
                supplied = value
            else:
                return False
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(supplied, self.config.password)


def _make_handler(dashboard: Dashboard) -> type[BaseHTTPRequestHandler]:
    application = dashboard.app

    class Handler(BaseHTTPRequestHandler):
        server_version = "WiFiGuard"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # -- plumbing -----------------------------------------------------

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s - %s", self.address_string(), fmt % args)

        def _send(
            self,
            status: HTTPStatus,
            body: bytes,
            content_type: str = "application/json",
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            # The dashboard loads nothing from anywhere else, so lock it down.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
            )
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            self._send(status, json.dumps(payload, default=str).encode("utf-8"))

        def _error(self, status: HTTPStatus, message: str) -> None:
            self._json({"error": message, "status": int(status)}, status)

        def _body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return {}
            if length <= 0:
                return {}
            if length > MAX_BODY:
                raise ValueError(f"request body is too large ({length} bytes)")
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"request body is not valid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def _authorise(self, *, write: bool) -> bool:
            if write and dashboard.config.readonly:
                self._error(HTTPStatus.FORBIDDEN, "the dashboard is in read-only mode")
                return False
            if dashboard.authorised(self.headers.get("Authorization")):
                return True
            self._send(
                HTTPStatus.UNAUTHORIZED,
                json.dumps({"error": "authentication required"}).encode(),
                extra={"WWW-Authenticate": 'Basic realm="WiFiGuard"'},
            )
            return False

        # -- routing ------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = urllib.parse.parse_qs(parsed.query)

            try:
                if not path.startswith("/api"):
                    self._serve_static(path)
                    return
                if not self._authorise(write=False):
                    return
                handler = self._route_get(path)
                if handler is None:
                    self._error(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")
                    return
                handler(query)
            except BrokenPipeError:
                return
            except Exception as exc:  # noqa: BLE001 - never leak a traceback
                log.exception("dashboard GET %s failed", path)
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_POST(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            try:
                if not self._authorise(write=True):
                    return
                body = self._body()
                handler = self._route_post(path)
                if handler is None:
                    self._error(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")
                    return
                handler(body)
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except WireGuardError as exc:
                self._error(HTTPStatus.CONFLICT, str(exc))
            except BrokenPipeError:
                return
            except Exception as exc:  # noqa: BLE001
                log.exception("dashboard POST %s failed", path)
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        def do_DELETE(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            try:
                if not self._authorise(write=True):
                    return
                if path.startswith("/api/vpn/peers/"):
                    name = urllib.parse.unquote(path.rsplit("/", 1)[-1])
                    application.vpn.remove_peer(name)
                    self._sync_vpn()
                    self._json({"removed": name})
                    return
                self._error(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")
            except WireGuardError as exc:
                self._error(HTTPStatus.NOT_FOUND, str(exc))
            except Exception as exc:  # noqa: BLE001
                log.exception("dashboard DELETE %s failed", path)
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        def _route_get(self, path: str) -> Callable[[dict], None] | None:
            routes: dict[str, Callable[[dict], None]] = {
                "/api/status": self._get_status,
                "/api/savings": self._get_savings,
                "/api/queries": self._get_queries,
                "/api/top": self._get_top,
                "/api/history": self._get_history,
                "/api/clients": self._get_clients,
                "/api/check": self._get_check,
                "/api/cache": self._get_cache,
                "/api/gateway": self._get_gateway,
                "/api/vpn/peers": self._get_peers,
                "/api/search": self._get_search,
            }
            if path in routes:
                return routes[path]
            if path.startswith("/api/vpn/peers/"):
                return self._get_peer_detail
            return None

        def _route_post(self, path: str) -> Callable[[dict], None] | None:
            return {
                "/api/allow": self._post_allow,
                "/api/block": self._post_block,
                "/api/blocklists/refresh": self._post_refresh,
                "/api/cache/flush": self._post_flush,
                "/api/vpn/peers": self._post_peer,
            }.get(path)

        # -- static -------------------------------------------------------

        def _serve_static(self, path: str) -> None:
            name = "dashboard.html" if path == "/" else path.lstrip("/")
            target = (WEB_ROOT / name).resolve()
            try:
                # Refuse anything that escapes the web root.
                target.relative_to(WEB_ROOT.resolve())
            except ValueError:
                self._error(HTTPStatus.FORBIDDEN, "forbidden")
                return
            if not target.is_file():
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            content_type, _ = mimetypes.guess_type(target.name)
            self._send(
                HTTPStatus.OK,
                target.read_bytes(),
                content_type or "application/octet-stream",
                extra={"Cache-Control": "no-cache"},
            )

        # -- read endpoints -----------------------------------------------

        def _get_status(self, _query: dict) -> None:
            self._json(application.status())

        def _get_savings(self, _query: dict) -> None:
            self._json(application.savings())

        def _get_queries(self, query: dict) -> None:
            self._json(
                {
                    "queries": application.query_log.recent_queries(
                        limit=_int(query, "limit", 100, maximum=1000),
                        client=_first(query, "client"),
                        action=_first(query, "action"),
                    )
                }
            )

        def _get_search(self, query: dict) -> None:
            term = _first(query, "q")
            if not term:
                self._error(HTTPStatus.BAD_REQUEST, "the `q` parameter is required")
                return
            self._json({"results": application.query_log.search(term, _int(query, "limit", 100, maximum=1000))})

        def _get_top(self, query: dict) -> None:
            action = _first(query, "action") or "block"
            self._json({"action": action, "top": application.query_log.top(action, _int(query, "limit", 20, maximum=200))})

        def _get_history(self, query: dict) -> None:
            self._json({"history": application.query_log.history(hours=_int(query, "hours", 24, maximum=720))})

        def _get_clients(self, _query: dict) -> None:
            payload = {"clients": application.query_log.clients()}
            if application.gateway is not None and application.gateway.dhcp is not None:
                payload["leases"] = [
                    lease.as_dict() for lease in application.gateway.dhcp.active_leases()
                ]
            self._json(payload)

        def _get_check(self, query: dict) -> None:
            name = _first(query, "name")
            if not name:
                self._error(HTTPStatus.BAD_REQUEST, "the `name` parameter is required")
                return
            self._json(application.engine.check(name, _first(query, "client") or "0.0.0.0"))

        def _get_cache(self, query: dict) -> None:
            limit = _int(query, "limit", 100, maximum=2000)
            self._json(
                {
                    "stats": {**application.cache.stats.as_dict(), "entries": len(application.cache)},
                    "entries": application.cache.snapshot()[:limit],
                }
            )

        def _get_gateway(self, _query: dict) -> None:
            if application.gateway is None:
                self._json({"enabled": False})
                return
            self._json({"enabled": True, **application.gateway.status()})

        def _get_peers(self, _query: dict) -> None:
            self._json({"peers": application.vpn.status()})

        def _get_peer_detail(self, query: dict) -> None:
            parts = self.path.split("?")[0].rstrip("/").split("/")
            name = urllib.parse.unquote(parts[4]) if len(parts) > 4 else ""
            fmt = parts[5] if len(parts) > 5 else "config"
            try:
                if fmt in ("config", "conf"):
                    self._send(
                        HTTPStatus.OK,
                        application.vpn.peer_config(name).encode("utf-8"),
                        "text/plain; charset=utf-8",
                        extra={"Content-Disposition": f'attachment; filename="{name}.conf"'},
                    )
                elif fmt == "qr.png":
                    self._send(HTTPStatus.OK, application.vpn.peer_qr(name).to_png(), "image/png")
                elif fmt == "qr.svg":
                    self._send(
                        HTTPStatus.OK,
                        application.vpn.peer_qr(name).to_svg().encode("utf-8"),
                        "image/svg+xml",
                    )
                else:
                    self._error(HTTPStatus.NOT_FOUND, f"unknown format {fmt!r}")
            except WireGuardError as exc:
                self._error(HTTPStatus.NOT_FOUND, str(exc))
            except qr.QRError as exc:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        # -- write endpoints ----------------------------------------------

        def _post_allow(self, body: dict) -> None:
            domain = _domain(body)
            application.add_local_rule(domain, allow=True)
            self._json({"allowed": domain, "rules": application.blocklists.rule_count})

        def _post_block(self, body: dict) -> None:
            domain = _domain(body)
            application.add_local_rule(domain, allow=False)
            self._json({"blocked": domain, "rules": application.blocklists.rule_count})

        def _post_refresh(self, _body: dict) -> None:
            started = time.time()
            application.load_blocklists(refresh=True)
            self._json(
                {
                    "rules": application.blocklists.rule_count,
                    "sources": len(application.blocklists.sources),
                    "elapsed_seconds": round(time.time() - started, 2),
                }
            )

        def _post_flush(self, _body: dict) -> None:
            name = _first_value(_body_domain(_body))
            dropped = application.cache.invalidate(name)
            self._json({"flushed": dropped, "name": name or "*"})

        def _post_peer(self, body: dict) -> None:
            name = str(body.get("name", "")).strip()
            if not name:
                raise ValueError("`name` is required")
            peer = application.vpn.add_peer(
                name,
                profile=body.get("profile", "full"),
                preshared=bool(body.get("preshared", True)),
                mobile=bool(body.get("mobile", False)),
                tether_subnet=str(body.get("tether_subnet", "")),
                note=str(body.get("note", "")),
            )
            self._sync_vpn()
            self._json({"peer": peer.public_view()}, HTTPStatus.CREATED)

        def _sync_vpn(self) -> None:
            """Push the peer list to the live interface, if there is one."""
            try:
                application.vpn.apply(Path(application.config.vpn.config_path))
            except WireGuardError as exc:
                log.warning("could not reload the WireGuard interface: %s", exc)

    return Handler


def _first(query: dict, key: str) -> str:
    values = query.get(key)
    return values[0].strip() if values else ""


def _int(query: dict, key: str, default: int, *, maximum: int | None = None) -> int:
    raw = _first(query, key)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"`{key}` must be a number, got {raw!r}") from exc
    if value < 1:
        raise ValueError(f"`{key}` must be positive, got {value}")
    return min(value, maximum) if maximum else value


def _domain(body: dict) -> str:
    domain = str(body.get("domain", "")).strip().lower().strip(".")
    if not domain:
        raise ValueError("`domain` is required")
    if "/" in domain or " " in domain:
        raise ValueError(f"{domain!r} is not a valid domain")
    return domain


def _body_domain(body: dict) -> str:
    return str(body.get("domain", "")).strip().lower().strip(".")


def _first_value(value: str) -> str | None:
    return value or None
