import Foundation

/// The only configuration accepted by the administrator helper. It contains no keys,
/// executable strings, filenames, PF fragments, hostnames, or network ranges.
public struct PFConfiguration: Codable, Equatable, Sendable {
    public let tunnelAddresses: [String]
    public let endpoints: [ResolvedEndpoint]

    public init(tunnelAddresses: [String], endpoints: [ResolvedEndpoint]) throws {
        guard !tunnelAddresses.isEmpty, tunnelAddresses.count <= 32,
              !endpoints.isEmpty, endpoints.count <= 128 else { throw PFPolicyError.configurationLimit }
        let addresses = try tunnelAddresses.map { text -> IPAddress in
            guard let address = IPAddress(text), Self.usable(address) else { throw PFPolicyError.invalidAddress }
            return address
        }
        guard endpoints.allSatisfy({ $0.port > 0 && Self.usable($0.address) }) else {
            throw PFPolicyError.invalidEndpoint
        }
        self.tunnelAddresses = Set(addresses.map(\.description)).sorted()
        self.endpoints = Array(Set(endpoints)).sorted {
            ($0.address.description, $0.port) < ($1.address.description, $1.port)
        }
    }

    public func validated() throws -> PFConfiguration {
        try PFConfiguration(tunnelAddresses: tunnelAddresses, endpoints: endpoints)
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(tunnelAddresses: values.decode([String].self, forKey: .tunnelAddresses),
                      endpoints: values.decode([ResolvedEndpoint].self, forKey: .endpoints))
    }

    private static func usable(_ address: IPAddress) -> Bool {
        switch address.family {
        case .ipv4: return address.bytes[0] != 0 && address.bytes[0] != 127 && address.bytes[0] < 224
        case .ipv6: return address.bytes.contains { $0 != 0 } && address.description != "::1" && address.bytes[0] != 0xff
        }
    }
}

public enum PFPolicyError: Error, LocalizedError, Equatable {
    case configurationLimit, invalidAddress, invalidEndpoint, invalidInterface
    case unsafeRootRules, foreignFilterRules, skippedInterface, unrecognizedInterfaceReport

    public var errorDescription: String? {
        switch self {
        case .configurationLimit: return "Use 1–32 numeric tunnel addresses and 1–128 numeric WireGuard server endpoints."
        case .invalidAddress: return "Tunnel addresses must be individual, usable numeric IPv4 or IPv6 addresses."
        case .invalidEndpoint: return "WireGuard servers must use usable numeric IP addresses and UDP ports from 1 to 65535."
        case .invalidInterface: return "The detected tunnel interface is not a valid macOS utun interface."
        case .unsafeRootRules: return "The active PF rules do not have the standard Apple anchor layout. Latch will not replace your firewall rules."
        case .foreignFilterRules: return "Another active PF filter could conflict with the VPN guard. Disable that filter before enabling Latch."
        case .skippedInterface: return "PF is configured to skip a network interface. Latch cannot enforce its network block with that bypass."
        case .unrecognizedInterfaceReport: return "PF returned an unrecognized interface report. Latch cannot verify that all interfaces are filtered."
        }
    }
}

public enum PFPolicy {
    public static let anchor = "com.apple/000.ensure-vpn"

    /// All passes are explicitly stateless. Incoming traffic is also constrained so
    /// later PF anchors cannot create floating states that bypass outgoing decisions.
    /// `trustedInterfaces` must come from the helper's current getifaddrs observation,
    /// never from the unprivileged application's JSON.
    public static func rules(configuration: PFConfiguration, trustedInterfaces: [String]) throws -> String {
        let config = try configuration.validated()
        guard trustedInterfaces.count <= 32,
              trustedInterfaces.allSatisfy(validTunnelInterface) else { throw PFPolicyError.invalidInterface }
        var rules = ["pass quick on lo0 all no state"]
        for interface in Set(trustedInterfaces).sorted() {
            for text in config.tunnelAddresses {
                // Validation above guarantees this conversion. Explicit host prefixes
                // prevent PF from treating an address as a wider subnet.
                let address = IPAddress(text)!
                let family = address.family == .ipv4 ? "inet" : "inet6"
                let host = text + (address.family == .ipv4 ? "/32" : "/128")
                rules.append("pass out quick on \(interface) \(family) from \(host) to any no state")
                rules.append("pass in quick on \(interface) \(family) from any to \(host) no state")
            }
        }
        // Reassembled packets are checked normally; unassembled fragments on the
        // physical link do not receive an endpoint or bootstrap exception.
        rules.append("block drop quick all fragment")
        for endpoint in config.endpoints {
            let family = endpoint.address.family == .ipv4 ? "inet" : "inet6"
            let host = endpoint.address.description + (endpoint.address.family == .ipv4 ? "/32" : "/128")
            rules.append("pass out quick \(family) proto udp from any to \(host) port = \(endpoint.port) no state")
            rules.append("pass in quick \(family) proto udp from \(host) port = \(endpoint.port) to any no state")
        }
        rules += [
            // No blanket LAN or DNS exception. DHCP unicast renewal is intentionally
            // excluded; clients can fall back to broadcast rebinding.
            "pass out quick inet proto udp from any port = 68 to 255.255.255.255/32 port = 67 no state",
            "pass in quick inet proto udp from any port = 67 to any port = 68 no state",
            "pass out quick inet6 proto udp from { ::/128, fe80::/10 } port = 546 to ff02::1:2/128 port = 547 no state",
            "pass in quick inet6 proto udp from fe80::/10 port = 547 to { fe80::/10, ff02::1:2/128 } port = 546 no state",
            "pass out quick inet6 proto icmp6 from { ::/128, fe80::/10 } to ff02::2/128 icmp6-type routersol no state",
            "pass out quick inet6 proto icmp6 from any to { fe80::/10, ff02::1:ff00:0/104 } icmp6-type neighbrsol no state",
            "pass out quick inet6 proto icmp6 from any to { fe80::/10, ff02::1/128 } icmp6-type neighbradv no state",
            "pass in quick inet6 proto icmp6 from fe80::/10 to any icmp6-type { routeradv, neighbrsol, neighbradv } no state",
            "pass in quick inet6 proto icmp6 from ::/128 to ff02::1:ff00:0/104 icmp6-type neighbrsol no state",
            "block drop in quick all",
            "block drop out quick all"
        ]
        return rules.joined(separator: "\n") + "\n"
    }

    /// Use the active root `pfctl -sr`, not /etc/pf.conf or a dry run, which may
    /// print unresolved anchor paths. The sole filter hook must be unconditional.
    public static func validateRootRules(_ text: String) throws {
        let rules = normalizedRules(text)
        let hook = "anchor \"com.apple/*\" all"
        let allowedScrub = ["scrub-anchor \"com.apple/*\" all", "scrub-anchor \"com.apple/*\" all fragment reassemble"]
        guard rules.filter({ $0 == hook }).count == 1,
              rules.allSatisfy({ $0 == hook || allowedScrub.contains($0) }),
              rules.count <= 2 else { throw PFPolicyError.unsafeRootRules }
    }

    /// Inspect every sibling recursively. Empty structural anchors are harmless;
    /// any active filter rule (including a pass without `quick`) is a conflict.
    public static func validateForeignRules(_ text: String) throws {
        for line in normalizedRules(text) {
            if line == "}" || line == "{" { continue }
            let pattern = #"^(?:anchor|nat-anchor|rdr-anchor|binat-anchor) "[A-Za-z0-9_./*\-]+" all(?: \{)?$"#
            guard line.range(of: pattern, options: .regularExpression) != nil else {
                throw PFPolicyError.foreignFilterRules
            }
        }
    }

    /// Translation can create state and alter addresses before filter evaluation.
    /// Only the stock, unconditional attachment points are compatible with v1.
    public static func validateRootTranslationRules(_ text: String) throws {
        let rules = normalizedRules(text)
        let allowed = ["nat-anchor \"com.apple/*\" all", "rdr-anchor \"com.apple/*\" all"]
        guard rules.count <= 2, Set(rules).count == rules.count,
              rules.allSatisfy(allowed.contains) else { throw PFPolicyError.foreignFilterRules }
    }

    /// PF skip flags bypass the entire ruleset. Only local loopback may be skipped.
    public static func validateInterfaces(_ text: String) throws {
        let lines = normalizedRules(text)
        let pattern = #"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}(?: \(skip\))?$"#
        guard lines.contains("lo0") || lines.contains("lo0 (skip)"),
              lines.allSatisfy({ $0.range(of: pattern, options: .regularExpression) != nil }) else {
            throw PFPolicyError.unrecognizedInterfaceReport
        }
        for line in lines where line.contains("(skip)") {
            guard line == "lo0 (skip)" else { throw PFPolicyError.skippedInterface }
        }
    }

    /// Compare the canonical output of `pfctl -n -v -a ANCHOR -f FILE` with the
    /// current `pfctl -a ANCHOR -sr`. This never tries to reinterpret PF semantics.
    public static func normalizedRules(_ text: String) -> [String] {
        text.components(separatedBy: .newlines).compactMap { raw in
            let line = raw.split(whereSeparator: \.isWhitespace).joined(separator: " ")
            return line.isEmpty ? nil : line
        }
    }

    private static func validTunnelInterface(_ name: String) -> Bool {
        name.hasPrefix("utun") && name.utf8.count <= 15 && name.count > 4 &&
            name.dropFirst(4).utf8.allSatisfy { (48...57).contains($0) }
    }
}
