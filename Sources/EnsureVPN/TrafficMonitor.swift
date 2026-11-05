import Darwin
import Foundation
import SystemConfiguration

struct TrafficRates: Equatable {
    var download: Double = 0
    var upload: Double = 0
    var interface: String?
    var isTunnel = false
    var available = false

    static func formatted(_ bytesPerSecond: Double) -> String {
        let rate = max(0, bytesPerSecond)
        if rate >= 1_000_000_000 { return String(format: "%.1f GB/s", rate / 1_000_000_000) }
        if rate >= 1_000_000 { return String(format: "%.1f MB/s", rate / 1_000_000) }
        if rate >= 1_000 { return String(format: "%.0f KB/s", rate / 1_000) }
        return String(format: "%.0f B/s", rate)
    }
}

/// Reads 64-bit kernel interface counters. Measuring does not generate any traffic.
struct TrafficMonitor {
    private var previous: (name: String, received: UInt64, sent: UInt64, time: TimeInterval)?

    mutating func sample(tunnelInterfaces: [String]) -> TrafficRates {
        let name = tunnelInterfaces.first ?? Self.primaryInterface()
        guard let name, let counts = Self.counters(for: name) else {
            previous = nil
            return TrafficRates(interface: name)
        }
        let now = ProcessInfo.processInfo.systemUptime
        defer { previous = (name, counts.received, counts.sent, now) }
        guard let previous, previous.name == name, now > previous.time,
              counts.received >= previous.received, counts.sent >= previous.sent else {
            return TrafficRates(interface: name, isTunnel: !tunnelInterfaces.isEmpty)
        }
        let elapsed = now - previous.time
        guard elapsed < 5 else { return TrafficRates(interface: name, isTunnel: !tunnelInterfaces.isEmpty) }
        return TrafficRates(download: Double(counts.received - previous.received) / elapsed,
                            upload: Double(counts.sent - previous.sent) / elapsed,
                            interface: name, isTunnel: !tunnelInterfaces.isEmpty, available: true)
    }

    private static func primaryInterface() -> String? {
        guard let store = SCDynamicStoreCreate(nil, "EnsureVPN.Traffic" as CFString, nil, nil) else { return nil }
        for key in ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] {
            if let values = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
               let name = values["PrimaryInterface"] as? String { return name }
        }
        return nil
    }

    private static func counters(for name: String) -> (received: UInt64, sent: UInt64)? {
        let index = if_nametoindex(name)
        guard index != 0 else { return nil }
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, Int32(index)]
        var length = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &length, nil, 0) == 0,
              length > 0, length < 4_194_304 else { return nil }
        var bytes = [UInt8](repeating: 0, count: length)
        guard sysctl(&mib, UInt32(mib.count), &bytes, &length, nil, 0) == 0 else { return nil }
        return bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset + 4 <= length {
                let messageLength = Int(buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
                guard messageLength >= 4, messageLength <= length - offset else { return nil }
                if buffer[offset + 3] == RTM_IFINFO2,
                   messageLength >= MemoryLayout<if_msghdr2>.size {
                    let header = buffer.loadUnaligned(fromByteOffset: offset, as: if_msghdr2.self)
                    if UInt32(header.ifm_index) == index {
                        return (header.ifm_data.ifi_ibytes, header.ifm_data.ifi_obytes)
                    }
                }
                offset += messageLength
            }
            return nil
        }
    }
}
