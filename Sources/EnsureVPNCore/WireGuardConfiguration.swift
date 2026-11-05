import Foundation

/// Only the public routing information needed by Latch, never WireGuard key material.
public struct WireGuardConfiguration: Codable, Sendable, Equatable {
    public let tunnelAddresses: [String]
    public let endpoints: [WireGuardEndpoint]

    public init(tunnelAddresses: [String], endpoints: [WireGuardEndpoint]) {
        self.tunnelAddresses = tunnelAddresses
        self.endpoints = endpoints
    }

    public static func parse(_ text: String) throws -> WireGuardConfiguration {
        guard text.utf8.count <= 1_048_576 else { throw ConfigurationError.fileTooLarge }
        enum Section { case none, interface, peer }
        var section = Section.none
        var addresses = [String]()
        var endpoints = [WireGuardEndpoint]()
        var foundInterface = false
        var peerHasEndpoint = false
        var peerCount = 0

        for (offset, rawLine) in text.components(separatedBy: .newlines).enumerated() {
            let lineNumber = offset + 1
            let line = String(rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0])
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            if line.hasPrefix("[") {
                if section == .peer && !peerHasEndpoint { throw ConfigurationError.missingEndpoint }
                switch line.lowercased() {
                case "[interface]":
                    guard !foundInterface && peerCount == 0 else { throw ConfigurationError.invalidStructure(lineNumber) }
                    foundInterface = true
                    section = .interface
                case "[peer]":
                    guard foundInterface else { throw ConfigurationError.invalidStructure(lineNumber) }
                    section = .peer
                    peerHasEndpoint = false
                    peerCount += 1
                    guard peerCount <= 128 else { throw ConfigurationError.tooManyEndpoints }
                default: throw ConfigurationError.invalidStructure(lineNumber)
                }
                continue
            }
            guard section != .none, let equal = line.firstIndex(of: "=") else {
                throw ConfigurationError.invalidStructure(lineNumber)
            }
            let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { throw ConfigurationError.invalidStructure(lineNumber) }

            if section == .interface && key == "address" {
                for entry in value.split(separator: ",", omittingEmptySubsequences: false) {
                    let parts = entry.trimmingCharacters(in: .whitespaces).split(separator: "/", omittingEmptySubsequences: false)
                    guard (1...2).contains(parts.count), let address = IPAddress(String(parts[0])) else {
                        throw ConfigurationError.invalidAddress(lineNumber)
                    }
                    if parts.count == 2 {
                        guard !parts[1].isEmpty, parts[1].allSatisfy(\.isNumber),
                              let prefix = Int(parts[1]), (0...(address.family == .ipv4 ? 32 : 128)).contains(prefix) else {
                            throw ConfigurationError.invalidAddress(lineNumber)
                        }
                    }
                    // An unspecified/multicast/loopback tunnel address cannot establish tunnel identity.
                    guard isUsableTunnelAddress(address) else { throw ConfigurationError.invalidAddress(lineNumber) }
                    if !addresses.contains(address.description) { addresses.append(address.description) }
                    guard addresses.count <= 32 else { throw ConfigurationError.tooManyAddresses }
                }
            } else if section == .peer && key == "endpoint" {
                guard !peerHasEndpoint else { throw ConfigurationError.invalidEndpoint(lineNumber) }
                guard let endpoint = WireGuardEndpoint.parse(value) else { throw ConfigurationError.invalidEndpoint(lineNumber) }
                endpoints.append(endpoint)
                peerHasEndpoint = true
            }
            // In particular, PrivateKey and PresharedKey are never copied into the returned model.
        }
        guard foundInterface else { throw ConfigurationError.missingInterface }
        guard !addresses.isEmpty else { throw ConfigurationError.missingAddress }
        guard peerCount > 0, peerHasEndpoint, !endpoints.isEmpty else { throw ConfigurationError.missingEndpoint }
        return WireGuardConfiguration(tunnelAddresses: addresses, endpoints: endpoints)
    }

    private static func isUsableTunnelAddress(_ ip: IPAddress) -> Bool {
        switch ip.family {
        case .ipv4:
            return ip.bytes[0] != 0 && ip.bytes[0] != 127 && ip.bytes[0] < 224
        case .ipv6:
            return ip.bytes.contains(where: { $0 != 0 }) && ip.description != "::1" && ip.bytes[0] != 0xff
        }
    }
}

public struct WireGuardEndpoint: Codable, Sendable, Equatable, Hashable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var displayName: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    public static func parse(_ value: String) -> WireGuardEndpoint? {
        let host: String
        let portText: String
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]"), value.index(after: close) < value.endIndex,
                  value[value.index(after: close)] == ":" else { return nil }
            let rawHost = String(value[value.index(after: value.startIndex)..<close])
            guard let ip = IPAddress(rawHost), ip.family == .ipv6 else { return nil }
            host = ip.description
            portText = String(value[value.index(close, offsetBy: 2)...])
        } else {
            let pieces = value.split(separator: ":", omittingEmptySubsequences: false)
            guard pieces.count == 2 else { return nil }
            let rawHost = String(pieces[0])
            if let ip = IPAddress(rawHost) {
                host = ip.description
            } else {
                guard validHostname(rawHost) else { return nil }
                host = rawHost.lowercased()
            }
            portText = String(pieces[1])
        }
        guard !portText.isEmpty, portText.utf8.allSatisfy({ (48...57).contains($0) }),
              let port = UInt16(portText), port > 0 else { return nil }
        return WireGuardEndpoint(host: host, port: port)
    }

    private static func validHostname(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253 else { return false }
        let name = value.hasSuffix(".") ? String(value.dropLast()) : value
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        // Reject dotted numeric strings that failed inet_pton rather than treating them as DNS names.
        guard !name.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) else { return false }
        return labels.allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
            label.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }
}

public enum ConfigurationError: Error, LocalizedError, Equatable {
    case fileTooLarge
    case invalidStructure(Int)
    case invalidAddress(Int)
    case invalidEndpoint(Int)
    case missingInterface
    case missingAddress
    case missingEndpoint
    case tooManyAddresses
    case tooManyEndpoints

    public var errorDescription: String? {
        switch self {
        case .fileTooLarge: return "The WireGuard configuration is too large. Choose a .conf file smaller than 1 MB."
        case .invalidStructure(let line): return "The WireGuard configuration has an invalid section or setting on line \(line)."
        case .invalidAddress(let line): return "The tunnel address on line \(line) is not a usable IPv4 or IPv6 address."
        case .invalidEndpoint(let line): return "The peer endpoint on line \(line) needs a host and port, such as vpn.example.com:51820."
        case .missingInterface: return "The WireGuard configuration needs an [Interface] section."
        case .missingAddress: return "The WireGuard configuration needs an Address in its [Interface] section."
        case .missingEndpoint: return "Every WireGuard peer needs an Endpoint so its connection can pass the network block."
        case .tooManyAddresses: return "The WireGuard configuration supports at most 32 tunnel addresses."
        case .tooManyEndpoints: return "The WireGuard configuration supports at most 128 peer endpoints."
        }
    }
}
