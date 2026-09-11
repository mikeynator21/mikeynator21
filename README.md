## SymbiVPN

A network-wide ad blocker, encrypted DNS resolver and portable VPN gateway —
it filters every device on the network without installing anything on any of
them, and follows me to whatever network I'm on.

Python 3.11 and the standard library, no dependencies, so it installs on a
Raspberry Pi, a laptop, or an Android phone under Termux without a compiler or
a package index.

- Blocks ads and trackers for the whole network, including trackers hiding
  behind first-party CNAMEs
- Encrypts every lookup that leaves the house over DoH/DoT, with optional
  public-key pinning
- Turns a laptop into a portable filtering router that rebuilds itself each
  time the uplink changes
- Carries the filter to a phone over WireGuard

→ **[mikeynator21/Symbivpn](https://github.com/mikeynator21/Symbivpn)**
