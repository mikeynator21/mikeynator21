# Your phone

Two separate things, which are easy to confuse:

1. **Keeping your phone filtered wherever it is** — on cellular, on a hotel's
   WiFi, on a friend's network. This works well and is the main event.
2. **Running WiFiGuard on the phone itself**, as a second node that covers for
   your laptop when it sleeps. This works, with real limits, described below.

## 1. Filtered anywhere, over WireGuard

Your phone connects back to a WiFiGuard node — the home hub, or your laptop —
and resolves through it from wherever it happens to be.

On the node:

```bash
sudo wifiguard vpn init --endpoint home.example.com
sudo wifiguard vpn add-peer phone --mobile
```

That prints a QR code in the terminal. In the WireGuard app: **Add tunnel →
Create from QR code**, point the camera at it, done. The dashboard shows the
same code if you would rather scan from a screen.

`--endpoint` is whatever your phone can dial from outside: a static IP, or a
dynamic-DNS name. You will need to forward UDP 51820 to the node on your
router.

### Choosing a profile

```bash
wifiguard vpn add-peer phone --profile dns-only --mobile
```

| Profile | What goes through the tunnel | Use it when |
|---|---|---|
| `full` | Everything | You want the network you are on to see nothing but encrypted traffic |
| `dns-only` | Only DNS | **Usually the right answer.** Ads and trackers are blocked everywhere, but video and downloads go out directly — no battery cost, no speed penalty, almost no data through your home line |
| `lan` | DNS plus your home networks | You also want to reach the printer or the NAS from outside |
| `hotspot-relay` | Everything, plus your tethering range routed back | Your phone shares its connection with other devices |

`dns-only` is the one to start with. It is the cheapest possible way to stay
filtered: the only thing taking the detour is a few hundred bytes of DNS.

Every peer gets a **pre-shared key** by default. It costs nothing and means
traffic recorded today is not readable by someone who breaks Curve25519 later.

### When your phone is the hotspot

If you tether other devices to your phone, `--profile hotspot-relay` routes the
tethering range back through the tunnel:

```bash
wifiguard vpn add-peer phone-hotspot --profile hotspot-relay --mobile
```

Whether the tethered devices actually inherit the tunnel depends on the phone,
and this is worth being clear about: **iOS Personal Hotspot generally does
share the VPN with tethered devices; Android often does not.** On Android
versions where tethered traffic bypasses the VPN, the phone itself is filtered
and the devices behind it are not. There is no way around that from outside the
phone — it is an OS routing decision. If you need the devices behind it
filtered, use the laptop gateway instead.

## 2. The phone as a second node

Your laptop sleeps. Your phone does not. Running a node on each means the
network keeps resolving when the laptop closes, and the phone — idle almost all
the time — does the work when the laptop is not around to.

### How the handoff works

There is no virtual IP and no failover dance. Every node serves DNS on its own
address all the time, and clients are handed the full list with the node that
should answer at the front. DNS clients already fail over between listed
resolvers; that machinery is decades old and is in every device.

What the cluster adds is deciding the order:

- Each node has a **priority**. Higher wins.
- A node set to `yield_when_idle` drops to the bottom when its device shows no
  sign of use, so a lower-priority always-on node moves to the front.
- Nodes **share cached answers**, so a name is fetched from upstream once per
  cluster rather than once per node.

Give the laptop the higher priority and let it yield:

```toml
# laptop
[cluster]
enabled = true
name = "laptop"
address = "10.9.0.1"
peers = ["10.9.0.3"]
priority = 90
yield_when_idle = true
idle_after = 300
secret = "..."
```

```toml
# phone
[cluster]
enabled = true
name = "phone"
address = "10.9.0.3"
peers = ["10.9.0.1"]
priority = 40
yield_when_idle = false
secret = "..."
```

Generate the secret once with `wifiguard cluster secret` and use the same value
on both. Without it, anything that can reach the port could inject cache
entries, which is a DNS-poisoning primitive — so it is required, not optional.

Check it:

```console
$ wifiguard cluster status
This node: laptop (10.9.0.1)
  priority     90 (effective 1)
  state        yielding -- idle for 812s
  answering    standby
  cache shared 1204 out, 890 in

  peers
    phone            10.9.0.3         priority 40   active    up  (4.1s ago)

  clients are handed these resolvers, in order:
    1. 10.9.0.3
    2. 10.9.0.1
```

### Installing on Android

Termux, no root:

```bash
pkg install git
git clone https://github.com/mikeynator21/wifiguard
bash wifiguard/deploy/termux-setup.sh
```

Then:

```bash
termux-wake-lock
wifiguard -c ~/.wifiguard/wifiguard.toml run
```

Install **Termux:Boot** to have it start after a reboot.

### The limits, plainly

Android without root **cannot**:

- bind port 53 (privileged), so the phone's resolver runs on 5353 and is
  reached over the VPN rather than transparently;
- install firewall rules, so the phone cannot be a transparent gateway the way
  the laptop can;
- guarantee it stays running — Android will kill background processes under
  memory pressure, and a wake lock only reduces this.

So the phone is a genuinely useful second node and a poor primary one. If you
want something that is always up, a Raspberry Pi at home is a better primary
than either device — see [deploy/examples/home-hub.toml](../deploy/examples/home-hub.toml).
