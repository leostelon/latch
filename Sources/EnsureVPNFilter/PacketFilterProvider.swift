import Darwin
import EnsureVPNCore
import Foundation
import Network
import NetworkExtension
import OSLog

/// The packet handler remains default-deny on physical interfaces at all times.
/// VPN detection in the menu app does not turn this policy on or off.
@objc(EnsureVPNPacketFilterProvider)
final class PacketFilterProvider: NEFilterPacketProvider {
    private let logger = Logger(subsystem: "dev.ensurevpn.app.filter", category: "PacketFilter")
    private let configurationLock = NSLock()
    private var configuration = Configuration.blocked
    private var running = false
    private var configurationObservation: NSKeyValueObservation?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        configurationLock.lock()
        running = true
        configuration = .blocked
        configurationLock.unlock()
        // Install a blocking handler before acknowledging readiness. Invalid or absent
        // configuration retains only the core policy's local network necessities.
        packetHandler = { [weak self] _, interface, direction, bytes, length in
            guard direction != .inbound else { return .allow }
            guard direction == .outbound, let self else { return .drop }
            return self.verdict(interface: interface, bytes: bytes, length: length)
        }
        configurationObservation = observe(\.filterConfiguration, options: [.initial, .new]) { [weak self] provider, _ in
            self?.replaceConfiguration(provider.filterConfiguration.vendorConfiguration)
        }
        logger.notice("Packet filter started. Direct traffic remains blocked except configured VPN transport and network setup.")
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        configurationObservation = nil
        configurationLock.lock()
        running = false
        configuration = .blocked
        configurationLock.unlock()
        // Keep the deny handler installed until the OS tears down the provider.
        // Once macOS disables this extension, this process cannot enforce anything.
        logger.notice("Packet filter stopping; reason: \(reason.rawValue, privacy: .public).")
        completionHandler()
    }

    private func replaceConfiguration(_ values: [String: Any]?) {
        let parsed = Configuration.parse(values)
        configurationLock.lock()
        configuration = running ? (parsed ?? .blocked) : .blocked
        configurationLock.unlock()
        if parsed == nil {
            logger.error("Missing or invalid VPN configuration. Tunnel and endpoint exceptions are closed.")
        } else {
            logger.notice("Applied VPN policy configuration.")
        }
    }

    private func verdict(interface: nw_interface_t, bytes: UnsafeRawPointer, length: Int) -> Verdict {
        guard length >= 0 else { return .drop }
        let index = nw_interface_get_index(interface)
        let name = String(cString: nw_interface_get_name(interface))
        let type = nw_interface_get_type(interface)
        let isLoopback = type == nw_interface_type_loopback && name == "lo0"

        configurationLock.lock()
        let current = configuration
        configurationLock.unlock()

        // Interface names and indexes are reused by macOS. Check the actual current
        // address assignment instead of trusting a stale, polled interface index.
        // This deliberately trades throughput for conservative trust in this version.
        let isTrusted = current.matchesTunnel(name: name, index: index)
        let policy = PacketPolicy(
            trustedInterfaceIndices: isTrusted ? [index] : [],
            endpoints: current.endpoints
        )
        let framing: PacketFraming
        if name.hasPrefix("utun") || isLoopback {
            framing = .rawIP
        } else if type == nw_interface_type_wifi || type == nw_interface_type_wired {
            framing = .ethernet
        } else {
            framing = .unknown
        }
        let allowed = policy.allows(
            packet: UnsafeRawBufferPointer(start: bytes, count: length),
            interfaceIndex: index,
            isLoopback: isLoopback,
            outbound: true,
            framing: framing
        )
        return allowed ? .allow : .drop
    }
}

private struct Configuration {
    let tunnelAddresses: Set<EnsureVPNCore.IPAddress>
    let endpoints: Set<ResolvedEndpoint>
    static let blocked = Configuration(tunnelAddresses: [], endpoints: [])

    static func parse(_ values: [String: Any]?) -> Configuration? {
        guard let values,
              let addresses = values["tunnelAddresses"] as? [String],
              !addresses.isEmpty, addresses.count <= 32,
              let endpointValues = values["endpoints"] as? [[String: Any]],
              !endpointValues.isEmpty, endpointValues.count <= 128 else { return nil }
        let parsedAddresses = addresses.compactMap(EnsureVPNCore.IPAddress.init)
        guard parsedAddresses.count == addresses.count else { return nil }
        var endpoints: Set<ResolvedEndpoint> = []
        for item in endpointValues {
            guard let addressString = item["address"] as? String,
                  let address = EnsureVPNCore.IPAddress(addressString),
                  let port = item["port"] as? Int,
                  let validPort = UInt16(exactly: port), validPort > 0 else { return nil }
            endpoints.insert(ResolvedEndpoint(address: address, port: validPort))
        }
        return Configuration(tunnelAddresses: Set(parsedAddresses), endpoints: endpoints)
    }

    func matchesTunnel(name: String, index: UInt32) -> Bool {
        guard !tunnelAddresses.isEmpty, name.hasPrefix("utun"),
              !name.dropFirst(4).isEmpty, name.dropFirst(4).allSatisfy(\.isNumber),
              index != 0, if_nametoindex(name) == index else { return false }
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let first = interfaces else { return false }
        defer { freeifaddrs(first) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let value = entry.pointee
            guard String(cString: value.ifa_name) == name,
                  value.ifa_flags & UInt32(IFF_UP) != 0,
                  value.ifa_flags & UInt32(IFF_POINTOPOINT) != 0,
                  let socketAddress = value.ifa_addr,
                  socketAddress.pointee.sa_family == UInt8(AF_INET)
                    || socketAddress.pointee.sa_family == UInt8(AF_INET6) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(socketAddress, socklen_t(socketAddress.pointee.sa_len),
                                     &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            guard result == 0 else { continue }
            // IPv6 scope suffixes identify a link, not part of the IP address bytes.
            let literal = String(cString: host).split(separator: "%", maxSplits: 1).first.map(String.init) ?? ""
            if let address = EnsureVPNCore.IPAddress(literal), tunnelAddresses.contains(address) { return true }
        }
        return false
    }
}
