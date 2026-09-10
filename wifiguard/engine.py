"""The filtering resolver: one query in, one decision and one answer out.

Order matters here, and it is chosen so that the cheapest and most private path
is taken first. A blocked name never reaches the network; a cached name never
reaches the network; a local or private name never reaches the network. Only
what is left is forwarded, over an encrypted channel, once.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from . import dnsmsg
from .blocklist import NO_MATCH, BlocklistManager
from .cache import CacheKey, DNSCache, SingleFlight
from .compat import CompatibilityGuard
from .policy import Decision, PolicyEngine
from .resolver import ResolutionError, UpstreamPool
from .stats import QueryLog, QueryRecord

log = logging.getLogger(__name__)

#: Firefox queries this name before enabling DNS-over-HTTPS. An NXDOMAIN is the
#: agreed signal for "this network filters DNS, do not bypass it", and honouring
#: it is what keeps Firefox from silently routing around us.
CANARY_DOMAIN = "use-application-dns.net"

#: Zones that must never be sent to a public resolver: they are meaningless
#: outside this network, and forwarding them leaks the local topology while
#: guaranteeing an NXDOMAIN in return.
LOCAL_ZONES = (
    "local",
    "localhost",
    "home.arpa",
    "internal",
    "lan",
    "intranet",
    "invalid",
    "test",
    "onion",
    "in-addr.arpa",
    "ip6.arpa",
)

_PRIVATE_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_PRIVATE_V6 = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class EngineConfig:
    #: How a blocked name is answered: "zero" (0.0.0.0), "nxdomain" or "refused".
    block_mode: str = "zero"
    block_ttl: int = 60
    #: Follow CNAME chains and block trackers hiding behind a first-party name.
    uncloak_cnames: bool = True
    #: Reject public names that resolve to private addresses (DNS rebinding).
    rebinding_protection: bool = True
    #: Names exempt from rebinding protection, for split-horizon setups.
    rebinding_allow: list[str] = field(default_factory=list)
    #: Answer queries for private zones locally instead of forwarding them.
    handle_local_zones: bool = True
    #: The suffix used for names learned from DHCP.
    local_suffix: str = "wifiguard.lan"
    #: Refuse ANY queries, which are only ever used for amplification.
    refuse_any: bool = True
    #: Serve an expired answer when upstream is unreachable.
    serve_stale: bool = True
    #: Carry a client's DNSSEC request through to upstream. Without it, a
    #: device that validates for itself cannot resolve anything at all.
    dnssec_passthrough: bool = True
    upstream_timeout: float = 5.0


class FilterEngine:
    """Answers DNS queries according to the blocklists, policy and cache."""

    def __init__(
        self,
        blocklists: BlocklistManager,
        policy: PolicyEngine,
        upstreams: UpstreamPool,
        cache: DNSCache,
        query_log: QueryLog,
        config: EngineConfig | None = None,
        compat: CompatibilityGuard | None = None,
    ) -> None:
        self.blocklists = blocklists
        #: Services devices break without. Consulted before anything else.
        # Compared against None rather than truth-tested: a guard with
        # protection switched off has no rules, so `or` would treat it as
        # absent and quietly substitute an enabled one.
        self.compat = CompatibilityGuard() if compat is None else compat
        self.policy = policy
        self.upstreams = upstreams
        self.cache = cache
        self.query_log = query_log
        self.config = config or EngineConfig()
        self._inflight = SingleFlight()
        #: Set by the application when clustering is on, so a name resolved
        #: here is also cached on the other nodes.
        self.cluster = None
        #: hostname -> address, learned from DHCP leases.
        self.local_names: dict[str, str] = {}
        self._local_lock = threading.RLock()
        cache._prefetch = self._schedule_prefetch

    # -- local names ------------------------------------------------------

    def set_local_names(self, mapping: dict[str, str]) -> None:
        """Publish DHCP-learned hostnames so devices can find each other."""
        with self._local_lock:
            self.local_names = {
                name.strip(".").lower(): address for name, address in mapping.items() if name
            }

    def _local_lookup(self, name: str) -> str | None:
        suffix = "." + self.config.local_suffix
        bare = name[: -len(suffix)] if name.endswith(suffix) else name
        with self._local_lock:
            return self.local_names.get(bare) or self.local_names.get(name)

    # -- the main entry point ---------------------------------------------

    def handle(self, query: bytes, client_address: str) -> bytes | None:
        """Answer one query. Returns the wire response, or None to stay silent."""
        started = time.perf_counter()
        if self.cluster is not None:
            # Serving a query is evidence this node is in use, which keeps it
            # from yielding to a standby node while it is doing real work.
            self.cluster.idle.mark_busy()

        try:
            header = dnsmsg.parse_header(query)
        except dnsmsg.DNSFormatError as exc:
            log.debug("dropping a malformed query from %s: %s", client_address, exc)
            return None

        if header.is_response:
            # Somebody is pointing responses at our listener; never reply, or we
            # become a reflector.
            return None

        if header.opcode != 0:
            return dnsmsg.build_error_response(query, dnsmsg.RCODE_NOTIMP)

        try:
            question = dnsmsg.first_question(query)
        except dnsmsg.DNSFormatError as exc:
            log.debug("dropping an unparseable question from %s: %s", client_address, exc)
            return dnsmsg.build_error_response(query, dnsmsg.RCODE_FORMERR)

        if question is None:
            return dnsmsg.build_error_response(query, dnsmsg.RCODE_FORMERR)

        name = question.name
        qtype_label = dnsmsg.type_name(question.qtype)

        # A client that says it will validate DNSSEC itself must be given the
        # signatures, or every lookup it makes fails.
        want_dnssec = self.config.dnssec_passthrough and dnsmsg.wants_dnssec(query)
        checking_disabled = header.flags & 0x0010 != 0

        def finish(response: bytes | None, action: str, decision: Decision, group: str, cached: bool) -> bytes | None:
            self.query_log.record(
                QueryRecord(
                    ts=time.time(),
                    client=client_address,
                    name=name if self.query_log.log_queries else "",
                    qtype=qtype_label,
                    action=action,
                    reason=decision.reason,
                    rule=decision.rule,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    cached=cached,
                    group_name=group,
                )
            )
            return response

        if question.qclass != dnsmsg.CLASS_IN:
            return finish(
                dnsmsg.build_error_response(query, dnsmsg.RCODE_REFUSED),
                "error", Decision("block", "unsupported class"), "default", False,
            )

        if self.config.refuse_any and question.qtype == dnsmsg.TYPE_ANY:
            return finish(
                dnsmsg.build_error_response(query, dnsmsg.RCODE_REFUSED),
                "error", Decision("block", "ANY refused"), "default", False,
            )

        # The canary: answering NXDOMAIN tells Firefox to leave DNS to us.
        if name == CANARY_DOMAIN or name.endswith("." + CANARY_DOMAIN):
            return finish(
                dnsmsg.build_error_response(query, dnsmsg.RCODE_NXDOMAIN),
                "block", Decision("block", "DoH canary", CANARY_DOMAIN), "default", False,
            )

        # Services a device breaks without -- its clock, its certificate checks,
        # its connectivity probe -- are allowed ahead of every other rule,
        # including a group's own block list and a schedule's block_all. Taking
        # a device's clock away does not restrict it, it just stops it working.
        essential = self.compat.match(name)
        protected = bool(essential) and essential.source.startswith("essential:")

        decision, group = self.policy.evaluate(name, client_address)

        if decision.blocked and not protected:
            return finish(self._block(query, question), "block", decision, group.name, False)

        if protected:
            decision = Decision("allow", "essential service", essential.rule)
        elif group.filtering and decision.action == "allow":
            allowed = self.blocklists.is_allowed(name) or essential
            if not allowed:
                blocked = self.blocklists.is_blocked(name)
                if blocked:
                    hit = Decision("block", "blocklist", blocked.rule)
                    return finish(self._block(query, question), "block", hit, group.name, False)

        if decision.action == "rewrite":
            response = self._rewrite(query, question, decision.target)
            if response is not None:
                return finish(response, "rewrite", decision, group.name, False)

        local = self._answer_locally(query, question)
        if local is not None:
            return finish(local, "local", Decision("allow", "local zone"), group.name, True)

        key = CacheKey(name, question.qtype, question.qclass, want_dnssec)
        hit = self.cache.get(key)
        if hit is not None:
            return finish(
                _prepare_reply(hit.wire, query),
                "allow", Decision("allow", "cache"), group.name, True,
            )

        response, from_cache = self._resolve(
            key, query, question, group.filtering, checking_disabled=checking_disabled
        )
        if response is None:
            return finish(
                dnsmsg.build_error_response(query, dnsmsg.RCODE_SERVFAIL),
                "error", Decision("allow", "upstream failure"), group.name, False,
            )

        # A tracker reached through a CNAME is blocked on the way back, once the
        # chain is visible.
        if group.filtering and self.config.uncloak_cnames and not protected:
            hidden = self._cname_block(response)
            if hidden is not None:
                return finish(self._block(query, question), "block", hidden, group.name, False)

        if self.config.rebinding_protection:
            rebinding = self._rebinding_block(name, response)
            if rebinding is not None:
                return finish(
                    dnsmsg.build_error_response(query, dnsmsg.RCODE_NXDOMAIN),
                    "block", rebinding, group.name, False,
                )

        return finish(_prepare_reply(response, query), "allow", Decision("allow"), group.name, from_cache)

    # -- decisions --------------------------------------------------------

    def _block(self, query: bytes, question: dnsmsg.Question) -> bytes:
        """Build the answer for a blocked name."""
        mode = self.config.block_mode
        if mode == "nxdomain":
            return dnsmsg.build_error_response(query, dnsmsg.RCODE_NXDOMAIN)
        if mode == "refused":
            return dnsmsg.build_error_response(query, dnsmsg.RCODE_REFUSED)

        # "zero": point the name at the unspecified address. The client fails to
        # connect immediately and locally, which is faster than a lookup failure
        # and does not push apps into retrying a different resolver.
        if question.qtype == dnsmsg.TYPE_A:
            return dnsmsg.build_address_response(query, dnsmsg.TYPE_A, "0.0.0.0", self.config.block_ttl)
        if question.qtype == dnsmsg.TYPE_AAAA:
            return dnsmsg.build_address_response(query, dnsmsg.TYPE_AAAA, "::", self.config.block_ttl)
        # Any other type gets an empty NOERROR, which is the correct way to say
        # "this name exists but has no record of that kind".
        return dnsmsg.build_address_response(query, question.qtype, None, self.config.block_ttl)

    def _rewrite(self, query: bytes, question: dnsmsg.Question, target: str) -> bytes | None:
        """Answer with the address of `target` under the original name.

        Used by safe search: the client asked for google.com and is handed the
        address of forcesafesearch.google.com without ever seeing the swap.
        """
        if question.qtype not in (dnsmsg.TYPE_A, dnsmsg.TYPE_AAAA):
            return None

        key = CacheKey(target, question.qtype, question.qclass)
        hit = self.cache.get(key)
        if hit is not None:
            addresses = dnsmsg.answer_addresses(hit.wire)
        else:
            try:
                upstream = self.upstreams.resolve(target, question.qtype, question.qclass)
            except ResolutionError as exc:
                log.debug("safe-search lookup of %s failed: %s", target, exc)
                return None
            self.cache.put(key, upstream)
            addresses = dnsmsg.answer_addresses(upstream)

        wanted_version = 6 if question.qtype == dnsmsg.TYPE_AAAA else 4
        for address in addresses:
            if ipaddress.ip_address(address).version == wanted_version:
                return dnsmsg.build_address_response(query, question.qtype, address, 300)
        return dnsmsg.build_address_response(query, question.qtype, None, 300)

    def _answer_locally(self, query: bytes, question: dnsmsg.Question) -> bytes | None:
        """Handle names that must not be forwarded to a public resolver."""
        if not self.config.handle_local_zones:
            return None

        name = question.name
        address = self._local_lookup(name)
        if address and question.qtype == dnsmsg.TYPE_A:
            return dnsmsg.build_address_response(query, dnsmsg.TYPE_A, address, 60)
        if address and question.qtype == dnsmsg.TYPE_AAAA:
            return dnsmsg.build_address_response(query, dnsmsg.TYPE_AAAA, None, 60)

        labels = name.split(".")
        for zone in LOCAL_ZONES:
            zone_labels = zone.split(".")
            if labels[-len(zone_labels) :] == zone_labels:
                # Reverse lookups for public addresses are legitimate, so only
                # private ranges are answered locally.
                if zone in ("in-addr.arpa", "ip6.arpa") and not _is_private_reverse(name):
                    return None
                return dnsmsg.build_error_response(query, dnsmsg.RCODE_NXDOMAIN)
        return None

    def _cname_block(self, response: bytes) -> Decision | None:
        try:
            targets = dnsmsg.cname_chain(response)
        except dnsmsg.DNSFormatError:
            return None
        for target in targets:
            if self.blocklists.is_allowed(target):
                return None
            hit = self.blocklists.is_blocked(target)
            if hit:
                return Decision("block", "CNAME cloaking", f"{target} ({hit.rule})")
        return None

    def _rebinding_block(self, name: str, response: bytes) -> Decision | None:
        """Reject a public name that resolves into this network's address space.

        This is the DNS half of a rebinding attack: a page loaded from the
        internet is handed an address on the local network and can then talk to
        the router or a printer from inside the browser's origin.
        """
        for zone in LOCAL_ZONES:
            if name == zone or name.endswith("." + zone):
                return None
        for allowed in self.config.rebinding_allow:
            allowed = allowed.strip(".").lower()
            if name == allowed or name.endswith("." + allowed):
                return None

        try:
            addresses = dnsmsg.answer_addresses(response)
        except dnsmsg.DNSFormatError:
            return None

        for address in addresses:
            parsed = ipaddress.ip_address(address)
            networks = _PRIVATE_V6 if parsed.version == 6 else _PRIVATE_V4
            if any(parsed in network for network in networks):
                return Decision("block", "DNS rebinding", f"{name} resolved to {address}")
        return None

    # -- upstream ---------------------------------------------------------

    def _resolve(
        self,
        key: CacheKey,
        query: bytes,
        question: dnsmsg.Question,
        filtering: bool,
        *,
        checking_disabled: bool = False,
    ) -> tuple[bytes | None, bool]:
        """Fetch from upstream, collapsing duplicate concurrent lookups."""
        is_leader, event = self._inflight.leader(key)

        if not is_leader:
            # Another thread is already asking for exactly this. Wait for it
            # rather than sending a second identical query.
            shared = self._inflight.collect(key, event, self.config.upstream_timeout + 1)
            if shared is not None:
                return shared, True
            cached = self.cache.get(key, allow_stale=self.config.serve_stale)
            return (cached.wire, True) if cached else (None, False)

        try:
            try:
                response = self.upstreams.resolve(
                    key.name, key.qtype, key.qclass,
                    want_dnssec=key.dnssec, checking_disabled=checking_disabled,
                )
            except ResolutionError as exc:
                log.warning("could not resolve %s: %s", key.name, exc)
                if self.config.serve_stale:
                    stale = self.cache.get(key, allow_stale=True)
                    if stale is not None:
                        log.info("serving a stale answer for %s while upstream is down", key.name)
                        self._inflight.publish(key, stale.wire)
                        return stale.wire, True
                self._inflight.publish(key, None)
                return None, False

            self.cache.put(key, response)
            if self.cluster is not None:
                self.cluster.share(key, response)
            self._inflight.publish(key, response)
            return response, False
        finally:
            self._inflight.cleanup(key)

    def _schedule_prefetch(self, key: CacheKey) -> None:
        """Refresh a popular entry in the background, just before it expires."""

        def refresh() -> None:
            try:
                response = self.upstreams.resolve(
                    key.name, key.qtype, key.qclass, want_dnssec=key.dnssec
                )
                self.cache.put(key, response)
                log.debug("prefetched %s/%s", key.name, dnsmsg.type_name(key.qtype))
            except (ResolutionError, dnsmsg.DNSFormatError) as exc:
                log.debug("prefetch of %s failed: %s", key.name, exc)
            finally:
                self.cache.finish_refresh(key)

        threading.Thread(target=refresh, name=f"prefetch-{key.name}", daemon=True).start()

    # -- introspection ----------------------------------------------------

    def check(self, name: str, client_address: str = "0.0.0.0") -> dict[str, object]:
        """Explain what would happen to `name`, without resolving it.

        Backs `wifiguard check <domain>` and the dashboard's "why was this
        blocked?" box, which is the question every ad blocker gets asked.
        """
        name = name.strip(".").lower()
        decision, group = self.policy.evaluate(name, client_address)
        result: dict[str, object] = {
            "name": name,
            "client": client_address,
            "group": group.name,
            "action": decision.action,
            "reason": decision.reason,
            "rule": decision.rule,
        }

        service = self.compat.explain(name)
        if service is not None:
            result.update(
                action="allow",
                reason="essential service",
                rule=self.compat.match(name).rule,
                source=service.title,
                essential=service.key,
                why=service.why,
            )
            return result

        if decision.action == "allow" and group.filtering:
            allowed = self.blocklists.is_allowed(name) or self.compat.match(name)
            if allowed:
                result.update(action="allow", reason="allowlist", rule=allowed.rule, source=allowed.source)
            else:
                blocked = self.blocklists.is_blocked(name)
                if blocked:
                    result.update(action="block", reason="blocklist", rule=blocked.rule, source=blocked.source)
        elif not group.filtering:
            result["reason"] = result["reason"] or "filtering is disabled for this group"
        return result


def _prepare_reply(response: bytes, query: bytes) -> bytes:
    """Match a cached or upstream answer to the client's query.

    The transaction ID and the exact bytes of the question name are the client's
    to choose, and a strict resolver checks that both come back unchanged.
    """
    header = dnsmsg.parse_header(query)
    reply = dnsmsg.set_message_id(response, header.id)

    try:
        _, question_end = dnsmsg.parse_questions(query)
        _, reply_question_end = dnsmsg.parse_questions(reply)
    except dnsmsg.DNSFormatError:
        return reply

    original = query[dnsmsg.HEADER_LEN : question_end]
    current = reply[dnsmsg.HEADER_LEN : reply_question_end]
    if original != current and len(original) == len(current):
        reply = reply[: dnsmsg.HEADER_LEN] + original + reply[reply_question_end:]
    return reply


def _is_private_reverse(name: str) -> bool:
    """Whether a reverse-lookup name covers a private address range."""
    if name.endswith("ip6.arpa"):
        # fc00::/7 and fe80::/10 reverse names begin with these nibbles.
        return name.startswith(("c.f.", "d.f.", "0.8.e.f", "1.8.e.f", "e.f.", "f.f."))
    labels = name.removesuffix(".in-addr.arpa").split(".")
    try:
        octets = [int(label) for label in reversed(labels)]
    except ValueError:
        return False
    if not octets:
        return False
    padded = octets + [0] * (4 - len(octets))
    try:
        address = ipaddress.ip_address(".".join(str(octet) for octet in padded[:4]))
    except ValueError:
        return False
    return any(address in network for network in _PRIVATE_V4)


def evaluate_at(engine: FilterEngine, name: str, client: str, moment: datetime) -> Decision:
    """Evaluate policy at a specific time, for testing schedules."""
    decision, _ = engine.policy.evaluate(name, client, now=moment)
    return decision
