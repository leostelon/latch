import Foundation
import Darwin

/// A numeric IP address. Names, CIDR prefixes and zone identifiers are deliberately excluded.
public struct IPAddress: Hashable, Codable, Sendable, CustomStringConvertible {
    public enum Family: Int, Codable, Sendable { case ipv4 = 4, ipv6 = 6 }

    public let family: Family
    public let bytes: [UInt8]

    public init?(_ value: String) {
        // Darwin may accept an IPv6 zone suffix; our persisted address identity must not.
        guard !value.isEmpty, value.utf8.allSatisfy({
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) || $0 == 58 || $0 == 46
        }) else { return nil }
        var storage = [UInt8](repeating: 0, count: 16)
        let v4 = storage.withUnsafeMutableBytes { buffer in
            value.withCString { inet_pton(AF_INET, $0, buffer.baseAddress!) }
        }
        if v4 == 1 {
            self.family = .ipv4
            self.bytes = Array(storage.prefix(4))
            return
        }
        let v6 = storage.withUnsafeMutableBytes { buffer in
            value.withCString { inet_pton(AF_INET6, $0, buffer.baseAddress!) }
        }
        guard v6 == 1 else { return nil }
        self.family = .ipv6
        self.bytes = storage
    }

    init(bytes: [UInt8], family: Family) {
        self.bytes = bytes
        self.family = family
    }

    public var description: String {
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = bytes.withUnsafeBytes { buffer in
            inet_ntop(family == .ipv4 ? AF_INET : AF_INET6, buffer.baseAddress!, &output, socklen_t(output.count))
        }
        guard result != nil else { return "" }
        return String(cString: output)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let address = IPAddress(text) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Expected a numeric IPv4 or IPv6 address.")
        }
        self = address
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
