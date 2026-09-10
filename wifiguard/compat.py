"""Keeping every device on the network working.

Network-wide filtering fails in practice for one reason far more often than any
other: it breaks something, the household notices before it notices the missing
ads, and the whole thing gets switched off. The breakage is rarely the ad
blocking itself -- it is a device losing a service it silently depends on.

Three things in particular turn a filtered network into a broken one:

* **Time.** A device whose NTP lookup fails has the wrong clock, so every TLS
  certificate looks invalid and nothing works at all. The device gives no clue
  why. This is the single most destructive thing a blocklist can do.
* **Certificate status.** OCSP and CRL lookups are made during TLS handshakes.
  Blocked, they either fail the handshake or stall it for seconds per
  connection, which reads as "the internet is slow".
* **Connectivity checks.** Phones, laptops and TVs probe a known URL to decide
  whether a network works. Block the probe and the device concludes the network
  is broken -- it will show a warning, refuse to stay connected, or fall back to
  cellular. Nothing else on the device works either way.

So the domains behind those are treated as essential: they are allowed ahead of
every blocklist, every category and every group rule, and it takes an explicit
configuration change to block them. They carry no advertising and no tracking,
which is what makes this a safe default rather than a hole.

Device profiles are separate and additive: the minimum a given class of device
needs to function, without its telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .blocklist import DomainSet, Match


@dataclass(frozen=True)
class EssentialService:
    """A service that devices break without."""

    key: str
    title: str
    why: str
    domains: tuple[str, ...]


#: Ordered roughly by how badly a device breaks when the lookup fails.
ESSENTIAL_SERVICES: tuple[EssentialService, ...] = (
    EssentialService(
        key="time",
        title="Network time (NTP)",
        why=(
            "A device with the wrong clock rejects every TLS certificate as "
            "not yet valid or expired, so nothing on it works and it gives no "
            "indication why."
        ),
        domains=(
            "pool.ntp.org", "ntp.org",
            "time.apple.com", "time-ios.apple.com", "time.euro.apple.com",
            "time.windows.com",
            "time.google.com", "time1.google.com", "time2.google.com",
            "time3.google.com", "time4.google.com",
            "time.android.com", "android.pool.ntp.org",
            "time.nist.gov", "time.cloudflare.com",
            "ntp.ubuntu.com", "ntp.msn.com", "time.samsungcloudsolution.com",
            "ntp.fritz.box", "time.sonos.com",
        ),
    ),
    EssentialService(
        key="certificates",
        title="Certificate status (OCSP and CRL)",
        why=(
            "Checked during TLS handshakes. Blocked, handshakes either fail "
            "outright or stall for seconds each, which people experience as the "
            "network being slow rather than filtered."
        ),
        domains=(
            "ocsp.digicert.com", "crl.digicert.com", "cacerts.digicert.com",
            "ocsp.sectigo.com", "crl.sectigo.com",
            "ocsp.comodoca.com", "crl.comodoca.com",
            "ocsp.usertrust.com", "crl.usertrust.com",
            "o.lencr.org", "r3.o.lencr.org", "e5.o.lencr.org",
            "x1.c.lencr.org", "e6.c.lencr.org",
            "ocsp.pki.goog", "pki.goog", "c.pki.goog", "crl.pki.goog",
            "ocsp.apple.com", "crl.apple.com", "valid.apple.com",
            "certs.apple.com", "certificatestatus.apple.com",
            "ocsp.godaddy.com", "crl.godaddy.com",
            "ocsp.globalsign.com", "crl.globalsign.com",
            "ocsp.entrust.net", "crl.entrust.net",
            "isrg.trustid.ocsp.identrust.com",
            "status.rapidssl.com", "status.geotrust.com",
            "ctldl.windowsupdate.com", "crl.microsoft.com",
            "www.microsoft.com",
        ),
    ),
    EssentialService(
        key="connectivity",
        title="Connectivity and captive-portal checks",
        why=(
            "Every operating system probes a known URL to decide whether the "
            "network works. A failed probe makes the device show a warning, "
            "refuse to stay connected, or fall back to mobile data."
        ),
        domains=(
            # Apple
            "captive.apple.com", "www.apple.com",
            "gsp1.apple.com", "gsp-ssl.ls.apple.com", "gspe1-ssl.ls.apple.com",
            # Android and Chrome OS
            "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
            "clients3.google.com", "clients4.google.com", "www.gstatic.com",
            "android.clients.google.com", "play.googleapis.com",
            # Windows
            "msftconnecttest.com", "www.msftconnecttest.com",
            "ipv6.msftconnecttest.com", "msftncsi.com", "www.msftncsi.com",
            "dns.msftncsi.com",
            # Firefox
            "detectportal.firefox.com",
            # Desktop Linux
            "nmcheck.gnome.org", "network-test.debian.org",
            "connectivity-check.ubuntu.com", "networkcheck.kde.org",
            # Amazon and Samsung devices
            "fireoscaptiveportal.com", "spectrum.s3.amazonaws.com",
            "connectivitycheck.samsungdm.com",
        ),
    ),
    EssentialService(
        key="push",
        title="Push notifications",
        why=(
            "Phones lose messages and alerts when these are blocked, and the "
            "network gets the blame. They carry notification delivery, not "
            "advertising."
        ),
        domains=(
            "push.apple.com", "courier.push.apple.com",
            "mtalk.google.com", "mtalk4.google.com", "alt1-mtalk.google.com",
            "alt2-mtalk.google.com", "alt3-mtalk.google.com",
            "alt4-mtalk.google.com", "alt5-mtalk.google.com",
            "alt6-mtalk.google.com", "alt7-mtalk.google.com",
            "alt8-mtalk.google.com",
            "fcm.googleapis.com", "android.apis.google.com",
            "notify.windows.com", "wns.windows.com",
        ),
    ),
    EssentialService(
        key="activation",
        title="Device setup and activation",
        why=(
            "A device that cannot reach these during setup cannot be set up at "
            "all -- and a factory-reset phone on a filtered network is a "
            "miserable way to discover that."
        ),
        domains=(
            "albert.apple.com", "static.ips.apple.com", "setup.icloud.com",
            "gs.apple.com", "humb.apple.com", "tbsc.apple.com",
            "sq-device.apple.com", "iprofiles.apple.com", "gdmf.apple.com",
            "mesu.apple.com", "appldnld.apple.com", "updates.cdn-apple.com",
            "swscan.apple.com", "swcdn.apple.com", "swdist.apple.com",
            "activation.sls.microsoft.com", "login.live.com",
            "account.live.com", "go.microsoft.com",
        ),
    ),
    EssentialService(
        key="dns-infrastructure",
        title="DNS and PKI infrastructure",
        why="Blocking these breaks name resolution and software updates generally.",
        domains=(
            "root-servers.net", "iana.org", "arin.net", "ripe.net",
            "windowsupdate.com", "update.microsoft.com",
            "deb.debian.org", "security.debian.org", "archive.ubuntu.com",
            "security.ubuntu.com",
        ),
    ),
)


@dataclass(frozen=True)
class DeviceProfile:
    """The minimum a class of device needs in order to work.

    Deliberately not "everything the vendor's device talks to": telemetry and
    advertising endpoints are left out, which is the whole point of running a
    filter. These are the domains without which the device is broken rather
    than merely quieter.
    """

    key: str
    title: str
    note: str
    domains: tuple[str, ...] = ()


DEVICE_PROFILES: tuple[DeviceProfile, ...] = (
    DeviceProfile(
        key="apple",
        title="iPhone, iPad, Mac, Apple TV, HomePod",
        note="Sync, FaceTime, iMessage and AirPlay. Apple's ad and analytics hosts are not included.",
        domains=(
            "icloud.com", "icloud-content.com", "cdn-apple.com",
            "apple-cloudkit.com", "me.com", "aaplimg.com",
            "courier.push.apple.com", "init.itunes.apple.com",
            "facetime.apple.com", "imessage.apple.com",
            "cl1.apple.com", "cl2.apple.com", "cl3.apple.com",
            "cl4.apple.com", "cl5.apple.com",
        ),
    ),
    DeviceProfile(
        key="android",
        title="Android phones and tablets",
        note="Play Store, sync and notifications. Ad and measurement hosts are not included.",
        domains=(
            "googleapis.com", "gvt1.com", "gvt2.com",
            "android.googleapis.com", "play.googleapis.com",
            "clients1.google.com", "clients2.google.com",
        ),
    ),
    DeviceProfile(
        key="windows",
        title="Windows PCs",
        note="Updates, activation and Store. Telemetry hosts are not included.",
        domains=(
            "windowsupdate.com", "delivery.mp.microsoft.com",
            "tlu.dl.delivery.mp.microsoft.com", "download.windowsupdate.com",
            "login.microsoftonline.com", "officecdn.microsoft.com",
        ),
    ),
    DeviceProfile(
        key="smart-tv",
        title="Smart TVs (Samsung, LG, Sony, Vizio, Roku, Fire TV)",
        note=(
            "Firmware, app stores and playback. Each of these platforms also "
            "runs heavy ad and viewing-habit collection, which stays blocked."
        ),
        domains=(
            "samsungcloudsolution.com", "samsungqbe.com", "samsungotn.net",
            "lgtvsdp.com", "lgtvcommon.com", "lgsmartad-cdn.lgeapi.com",
            "sonyentertainmentnetwork.com", "sony.net",
            "roku.com", "rokutime.com", "roku-cdn.com",
            "amazonvideo.com", "aiv-cdn.net", "atv-ps.amazon.com",
            "vizio-atv.tv",
        ),
    ),
    DeviceProfile(
        key="console",
        title="PlayStation, Xbox and Nintendo Switch",
        note="Online play, updates and store access.",
        domains=(
            "playstation.net", "playstation.com", "sonyentertainmentnetwork.com",
            "np.community.playstation.net",
            "xboxlive.com", "xbox.com", "xboxservices.com",
            "nintendo.net", "nintendo.com", "nintendowifi.net",
            "cdn.nintendo.net", "srv.nintendo.net",
        ),
    ),
    DeviceProfile(
        key="voice-assistant",
        title="Alexa and Google Home",
        note="Voice services and device control.",
        domains=(
            "amazonalexa.com", "alexa.amazon.com", "avs-alexa-na.amazon.com",
            "device-metrics-us.amazon.com",
            "clients4.google.com", "googlezip.net",
            "home.google.com", "assistant.google.com",
        ),
    ),
    DeviceProfile(
        key="printer",
        title="Network printers and scanners",
        note="Cloud printing, firmware and supply-level reporting.",
        domains=(
            "hpeprint.com", "hpconnected.com", "hp.com",
            "canon.com", "bjnp.canon", "epson.com", "epsonconnect.com",
            "brother.com", "brothercloud.com",
        ),
    ),
    DeviceProfile(
        key="smart-home",
        title="Smart plugs, bulbs, cameras and speakers",
        note=(
            "Vendor control planes. Most of these devices only work at all "
            "while they can reach their vendor, which is a fact about the "
            "devices, not about the filter."
        ),
        domains=(
            "tuyaus.com", "tuyaeu.com", "tuyacn.com", "tuya.com",
            "meethue.com", "hue.philips.com",
            "sonos.com", "sonos.radio",
            "nest.com", "home.nest.com", "dropcam.com",
            "ring.com", "a2z.com",
            "wyze.com", "wyzecam.com",
            "shelly.cloud", "shelly.cloud.allterco.com",
            "tplinkcloud.com", "tplinkra.com",
        ),
    ),
    DeviceProfile(
        key="streaming",
        title="Chromecast, Apple TV, Fire Stick",
        note="Casting and playback. Ad delivery within the apps is not covered by DNS filtering either way.",
        domains=(
            "googlecast.com", "gstatic.com", "googlevideo.com",
            "nflxvideo.net", "nflxso.net", "netflix.com",
            "spotify.com", "scdn.co", "spotifycdn.com",
            "ttvnw.net", "jtvnw.net",
        ),
    ),
)

PROFILE_KEYS = tuple(profile.key for profile in DEVICE_PROFILES)
ESSENTIAL_KEYS = tuple(service.key for service in ESSENTIAL_SERVICES)


def essential_domains(exclude: set[str] | None = None) -> list[str]:
    """Every essential domain, optionally minus some categories."""
    exclude = exclude or set()
    return [
        domain
        for service in ESSENTIAL_SERVICES
        if service.key not in exclude
        for domain in service.domains
    ]


def profile_domains(keys: list[str] | tuple[str, ...]) -> list[str]:
    """The domains for the named device profiles."""
    wanted = set(keys)
    if "all" in wanted:
        wanted = set(PROFILE_KEYS)
    return [
        domain
        for profile in DEVICE_PROFILES
        if profile.key in wanted
        for domain in profile.domains
    ]


def unknown_profiles(keys: list[str] | tuple[str, ...]) -> list[str]:
    return sorted(set(keys) - set(PROFILE_KEYS) - {"all"})


class CompatibilityGuard:
    """Answers "would blocking this break the device?" for one query.

    Matched ahead of every other rule, so no blocklist, category or group rule
    can take a device's clock or certificate checks away by accident.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        exclude_services: set[str] | None = None,
        profiles: list[str] | tuple[str, ...] = (),
        extra: list[str] | tuple[str, ...] = (),
    ) -> None:
        self.enabled = enabled
        self.exclude_services = exclude_services or set()
        self.profiles = list(profiles)

        self.rules = DomainSet()
        self._service_of: dict[str, str] = {}

        if not enabled:
            return

        for service in ESSENTIAL_SERVICES:
            if service.key in self.exclude_services:
                continue
            for domain in service.domains:
                self.rules.add_suffix(domain, f"essential:{service.key}")
                self._service_of[domain] = service.key

        for profile in DEVICE_PROFILES:
            if profile.key in self.profiles or "all" in self.profiles:
                for domain in profile.domains:
                    self.rules.add_suffix(domain, f"device:{profile.key}")
                    self._service_of.setdefault(domain, f"device:{profile.key}")

        for domain in extra:
            cleaned = domain.strip().lstrip("*.").lower()
            if cleaned:
                self.rules.add_suffix(cleaned, "compat:config")

    def __len__(self) -> int:
        return len(self.rules)

    def match(self, name: str) -> Match:
        if not self.enabled:
            from .blocklist import NO_MATCH

            return NO_MATCH
        return self.rules.match(name)

    def explain(self, name: str) -> EssentialService | None:
        """Which essential service a name belongs to, for diagnostics."""
        hit = self.match(name)
        if not hit or not hit.source.startswith("essential:"):
            return None
        key = hit.source.split(":", 1)[1]
        for service in ESSENTIAL_SERVICES:
            if service.key == key:
                return service
        return None

    def summary(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "rules": len(self.rules),
            "services": [
                {
                    "key": service.key,
                    "title": service.title,
                    "domains": len(service.domains),
                    "active": service.key not in self.exclude_services,
                }
                for service in ESSENTIAL_SERVICES
            ],
            "profiles": [
                {
                    "key": profile.key,
                    "title": profile.title,
                    "domains": len(profile.domains),
                    "active": profile.key in self.profiles or "all" in self.profiles,
                }
                for profile in DEVICE_PROFILES
            ],
        }
