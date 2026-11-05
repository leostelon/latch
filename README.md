# Latch

A native macOS menu bar guard for WireGuard. Turn **Always-on VPN** on to restrict internet traffic to your configured tunnel, with narrow exceptions that let WireGuard reconnect. Turn it off to restore normal network routing. The menu also shows current upload and download rates.

Latch uses macOS's built-in Packet Filter (PF) through a local administrator-authorized helper. **No Apple developer account, Network Extension signing, or provisioning profile is needed for this local build.** Building, opening the app, and running the automated checks do not change firewall settings. Enabling Always-on VPN does.

This is an early local-use implementation. Its rules and validation checks are tested, but live leak prevention, sleep/wake, reconnects, and recovery still need testing on the target Mac. An enabled switch is not proof of a working WireGuard handshake or complete network protection.

## Build and open

Requires macOS 14 or later, Swift 6 Command Line Tools, and Python 3 for bundling. There are no downloaded package dependencies.

```sh
swift run EnsureVPNChecks
swift run EnsureVPNPFChecks
./scripts/build-app.sh
open dist/Latch.app
```

The app lives in the menu bar without a Dock icon. `CONFIGURATION=debug ./scripts/build-app.sh` produces a debug bundle. The default build signs the executable and helper ad hoc for local use. Internal executable names, bundle IDs, and helper paths retain `EnsureVPN`/`dev.ensurevpn` to preserve compatibility with earlier local builds; the app's public name is Latch.

Optional ordinary Developer ID signing is supported without provisioning profiles:

```sh
SIGNING_IDENTITY='Developer ID Application: Your Name (YOURTEAMID)' ./scripts/build-app.sh
```

That is optional packaging for distribution, not a requirement for PF enforcement. The original Network Extension implementation remains in `Sources/EnsureVPNFilter` as reference code. It is not included in `Latch.app`, and its legacy entitlements and signing-profile script are not used by the current build.

## Set up WireGuard

1. Install WireGuard for macOS and configure the tunnel there. Latch does not implement a VPN or manage WireGuard keys.
2. Import that tunnel's `.conf` file into Latch. Only interface addresses and peer server endpoints are saved; private keys and preshared keys are discarded. The original file still contains secrets, so keep it private.
3. Review the resolved server IP addresses and UDP ports under connection exceptions.
4. Turn on **Always-on VPN** and approve the macOS administrator prompt. Latch checks the existing PF setup, installs its helper, loads its own rules, and resets existing tracked connections before reporting verified rules.
5. Activate the matching tunnel in WireGuard. When the tunnel disconnects, ordinary physical-interface traffic remains blocked rather than being allowed until a status poll notices.

**Enabling the guard resets PF's global connection-state table.** This can interrupt existing connections, including other applications' sessions. The reset is necessary because old PF states can otherwise bypass new rules. It happens on initial activation and when the helper needs to reacquire enforcement after a reboot or PF reset; ordinary status polling and tunnel updates do not reset all states.

For a full internet tunnel, WireGuard should route `0.0.0.0/0` and, when supported, `::/0`. Split-tunnel traffic excluded from WireGuard is blocked rather than sent directly. DNS must be reachable inside the tunnel; there is no broad cleartext DNS exception.

For reliable reconnects, configure a **numeric server IP in WireGuard itself**, then export and import that configuration into Latch. Latch can resolve a hostname to build exceptions, but it does not populate WireGuard's DNS cache. After that cache expires, WireGuard may be unable to reconnect because direct DNS is blocked. Reimport after changing a server IP or port, with Always-on VPN off.

## What the guard permits

The PF policy permits:

- Traffic on currently matched `utun` interfaces, restricted to the imported tunnel addresses.
- Outgoing UDP to each configured WireGuard server IP and port, and incoming UDP replies from that server IP and port.
- Local loopback traffic, DHCP client broadcast/reply traffic, DHCPv6 local traffic, and limited IPv6 neighbor discovery. ARP is outside PF's IP filtering and remains available.

Other incoming and outgoing IP traffic is blocked. **Inbound traffic is restricted too** so later PF rules cannot create floating connection states that bypass the outgoing block. Every allowed rule is stateless. Ordinary LAN access, direct DNS, arbitrary ICMP, and IPv6 internet traffic have no general bypass. Some uncommon networking behavior, including DHCP unicast renewal and fragmented physical-link traffic, is deliberately restricted.

Any process can send UDP to an allowed server IP and port; these are address-based exceptions, not cryptographic identification of WireGuard packets. Matching an interface's assigned addresses also does not prove which VPN provider owns it or that its handshake is healthy. A different tunnel with the same addresses could match.

## Existing firewall rules and status

Latch attaches only its `com.apple/000.ensure-vpn` anchor beneath the standard Apple PF wildcard. It never replaces `/etc/pf.conf` or reloads the main ruleset. Setup fails visibly if the active layout is unsupported, a non-loopback interface is skipped by PF, or active foreign filtering/NAT/redirection could conflict with the guard. Internet Sharing, AirDrop, or another firewall may introduce incompatible rules. Resolve the conflict before enabling Latch; the app does not silently overwrite those rules.

The privileged helper checks the actual PF enabled state, anchor contents, interface matches, and compatibility conditions. It publishes a root-owned status file; the menu rejects stale or incorrectly owned status as unverified. This is stronger than displaying a saved preference, but it is still a configuration check rather than an independent observation of every packet leaving the Mac.

The helper runs under `launchd` and continues after the menu app quits. PF rules remain installed if the UI closes. The helper reapplies enabled protection after reboot, but **there is no guarantee of protection before the helper starts during boot**. Another administrator or system service can disable PF or alter rules; the helper detects/reports changes, and some failures leave existing block rules in place. Test these behaviors before relying on the guard.

## Upload and download rates

Rates come from changes in macOS's 64-bit interface byte counters. Latch prefers the matched tunnel interface; otherwise it uses the primary network interface. The displayed values describe observed traffic on that interface, not a bandwidth or speed test, and measurement generates no internet traffic. Interface changes, sleep, or missing samples temporarily show an unavailable reading instead of a fabricated rate.

## Restore connectivity

Turn **Always-on VPN** off in Latch and approve the administrator prompt. This removes only Latch's anchor rules and releases only its own PF enable reference. Other firewall settings remain in place. Disabling Latch restores normal routing; it does not disconnect WireGuard itself.

If the menu app is unavailable, use the installed helper:

```sh
sudo /Library/PrivilegedHelperTools/dev.ensurevpn.helper disable
```

If necessary, the bundled helper has the same recovery command:

```sh
sudo '/path/to/Latch.app/Contents/Helpers/EnsureVPNHelper' disable
```

Do not use a global `pfctl -d` or flush all firewall rules as Latch recovery; that would also change protections owned by macOS or other software. Disable the guard before deleting the app. The installed daemon can remain idle after disabling; deleting the UI alone does not remove its protection or helper.

Administrator-only diagnostics:

```sh
sudo /Library/PrivilegedHelperTools/dev.ensurevpn.helper preflight
sudo /Library/PrivilegedHelperTools/dev.ensurevpn.helper status
```

`preflight` only reads PF configuration. `status` reads PF configuration and updates the helper's status file; neither enables the guard. The helper accepts a validated base64 JSON policy for `enable`, but normal setup should use the menu app so the connection reset and administrator authorization are visible.

Installed files retain stable internal names:

| Path | Purpose |
| --- | --- |
| `/Library/PrivilegedHelperTools/dev.ensurevpn.helper` | Root-owned helper executable |
| `/Library/LaunchDaemons/dev.ensurevpn.helper.plist` | Background watcher registration |
| `/Library/Application Support/EnsureVPN/policy.json` | Protected policy and PF ownership record |
| `/Library/Application Support/EnsureVPN/status.json` | Readable, root-owned verification status |

## Verification

`swift run EnsureVPNChecks` tests WireGuard parsing and the retained packet-policy code. `swift run EnsureVPNPFChecks` tests current PF configuration validation, generated rule structure, firewall compatibility checks, and Apple's actual PF parser using **dry runs only**. Full Xcode also provides the Swift Testing framework for `swift test`; Command Line Tools alone may not include it.

Live validation requires a test Mac and ideally a second machine or router to observe physical traffic. Check IPv4 and IPv6, DNS, UDP and TCP, established connections, WireGuard disconnect/reconnect, Wi-Fi changes, endpoint IP changes, sleep/wake, UI/helper termination, boot, and conflicting firewall rules. Verify both the documented exceptions and that ordinary traffic cannot escape the tunnel. Keep the local recovery command available during testing.

## Source map

| Location | Purpose |
| --- | --- |
| `Sources/EnsureVPN` | Latch menu UI, tunnel import/detection, traffic counters, administrator authorization |
| `Sources/EnsureVPNCore/PFPolicy.swift` | Validated configuration and stateless PF rule generation |
| `Sources/EnsureVPNHelper` | Protected helper installation, PF control, watcher, verification and recovery |
| `Tests/EnsureVPNPFChecks` | Current PF backend checks and dry-run syntax validation |
| `Tests/EnsureVPNChecks` | Shared parser and packet-policy checks for Command Line Tools |
| `Sources/EnsureVPNFilter` | Previous Network Extension implementation, not bundled |
| `Packaging`, `scripts` | Local app bundle creation; legacy NE signing references are unused |

Apple recognizes PF as an advanced user/administrator facility, but does not consider it a supported API for broadly distributed software. This local version deliberately uses that facility with conservative compatibility checks. See [TN3165: Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api).
