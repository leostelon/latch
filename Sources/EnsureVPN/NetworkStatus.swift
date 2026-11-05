import Foundation
import Darwin
import EnsureVPNCore

struct TunnelObservation: Equatable {
    var interfaces: [String] = []
    var isPresent: Bool { !interfaces.isEmpty }

    static func read(addresses: [String], inventory: [String: Set<String>]) -> TunnelObservation {
        let interfaces = addresses.compactMap(canonicalIP).flatMap { inventory[$0] ?? [] }
        return .init(interfaces: Set(interfaces).sorted())
    }

    static func inventory() -> [String: Set<String>] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { return [:] }
        defer { freeifaddrs(first) }
        var matches: [String: Set<String>] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            let item = current.pointee
            let name = String(cString: item.ifa_name)
            guard name.hasPrefix("utun"), !name.dropFirst(4).isEmpty,
                  name.dropFirst(4).allSatisfy(\.isNumber), item.ifa_flags & UInt32(IFF_UP) != 0,
                  item.ifa_flags & UInt32(IFF_POINTOPOINT) != 0,
                  let address = item.ifa_addr,
                  address.pointee.sa_family == AF_INET || address.pointee.sa_family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host,
                              socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let value = String(cString: host).components(separatedBy: "%")[0]
            if let normalized = canonicalIP(value) { matches[normalized, default: []].insert(name) }
        }
        return matches
    }
}

func canonicalIP(_ string: String) -> String? {
    var v4 = in_addr()
    var v6 = in6_addr()
    var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    if inet_pton(AF_INET, string, &v4) == 1 {
        inet_ntop(AF_INET, &v4, &output, socklen_t(output.count))
    } else if inet_pton(AF_INET6, string, &v6) == 1 {
        inet_ntop(AF_INET6, &v6, &output, socklen_t(output.count))
    } else { return nil }
    return String(cString: output)
}

struct ServerException: Codable, Hashable, Sendable {
    let address: String
    let port: Int
}

enum EndpointResolver {
    static func resolve(host: String, port: Int) throws -> [ServerException] {
        if let address = canonicalIP(host) { return [.init(address: address, port: port)] }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        var result: UnsafeMutablePointer<addrinfo>?
        let error = getaddrinfo(host, String(port), &hints, &result)
        guard error == 0, let result else {
            throw NSError(domain: "EnsureVPN", code: Int(error), userInfo: [NSLocalizedDescriptionKey:
                "Could not resolve the WireGuard server. Connect to the internet and import the configuration again."])
        }
        defer { freeaddrinfo(result) }
        var values = Set<ServerException>()
        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let current = cursor {
            defer { cursor = current.pointee.ai_next }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(current.pointee.ai_addr, current.pointee.ai_addrlen, &buffer,
                           socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0,
               let address = canonicalIP(String(cString: buffer)) {
                values.insert(.init(address: address, port: port))
            }
        }
        guard !values.isEmpty else {
            throw NSError(domain: "EnsureVPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "The VPN server has no usable IP addresses."])
        }
        return values.sorted { $0.address < $1.address }
    }
}
