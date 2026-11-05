import Foundation

public enum PacketFraming: Sendable {
    case rawIP
    case ethernet
    case unknown
}

public struct ResolvedEndpoint: Hashable, Codable, Sendable {
    public let address: IPAddress
    public let port: UInt16

    public init(address: IPAddress, port: UInt16) {
        self.address = address
        self.port = port
    }
}

/// Immutable policy, suitable for a snapshot shared by concurrent packet callbacks.
/// The provider is responsible for obtaining trusted interface indices from the configured tunnel addresses.
public struct PacketPolicy: Sendable {
    public let trustedInterfaceIndices: Set<UInt32>
    public let endpoints: Set<ResolvedEndpoint>

    public init(trustedInterfaceIndices: Set<UInt32> = [], endpoints: Set<ResolvedEndpoint> = []) {
        self.trustedInterfaceIndices = trustedInterfaceIndices
        self.endpoints = endpoints
    }

    public func allows(packet: Data, interfaceIndex: UInt32, isLoopback: Bool,
                       outbound: Bool, framing: PacketFraming = .rawIP) -> Bool {
        packet.withUnsafeBytes {
            allows(packet: $0, interfaceIndex: interfaceIndex, isLoopback: isLoopback, outbound: outbound, framing: framing)
        }
    }

    public func allows(packet: UnsafeRawBufferPointer, interfaceIndex: UInt32, isLoopback: Bool,
                       outbound: Bool, framing: PacketFraming = .rawIP) -> Bool {
        // Trust the actual egress interface, never the packet's source address alone.
        if !outbound || isLoopback { return true }
        if interfaceIndex != 0 && trustedInterfaceIndices.contains(interfaceIndex) { return true }
        let bytes = packet.bindMemory(to: UInt8.self)
        let ipStart: Int
        switch framing {
        case .rawIP: ipStart = 0
        case .unknown: return false
        case .ethernet:
            guard bytes.count >= 14 else { return false }
            var etherType = u16(bytes, 12)
            var offset = 14
            var tagCount = 0
            while etherType == 0x8100 || etherType == 0x88a8 {
                guard tagCount < 2, bytes.count >= offset + 4 else { return false }
                etherType = u16(bytes, offset + 2)
                offset += 4
                tagCount += 1
            }
            if etherType == 0x0806 { return validARP(bytes, start: offset) }
            guard etherType == 0x0800 || etherType == 0x86dd,
                  bytes.count > offset,
                  bytes[offset] >> 4 == (etherType == 0x0800 ? 4 : 6) else { return false }
            ipStart = offset
        }
        guard bytes.count > ipStart else { return false }
        switch bytes[ipStart] >> 4 {
        case 4: return allowsIPv4(bytes, start: ipStart)
        case 6: return allowsIPv6(bytes, start: ipStart)
        default: return false
        }
    }

    private func allowsIPv4(_ bytes: UnsafeBufferPointer<UInt8>, start: Int) -> Bool {
        guard bytes.count - start >= 20 else { return false }
        let headerLength = Int(bytes[start] & 0x0f) * 4
        let totalLength = Int(u16(bytes, start + 2))
        // IP options may include source routing, which defeats a destination-only exception.
        guard headerLength == 20, totalLength >= headerLength + 8,
              totalLength <= bytes.count - start,
              // Fragments cannot establish a complete, trustworthy UDP destination.
              u16(bytes, start + 6) & 0xbfff == 0,
              bytes[start + 9] == 17 else { return false }
        let udp = start + headerLength
        guard Int(u16(bytes, udp + 4)) == totalLength - headerLength else { return false }
        let destination = IPAddress(bytes: Array(bytes[(start + 16)..<(start + 20)]), family: .ipv4)
        let destinationPort = u16(bytes, udp + 2)
        if destinationPort != 0 && endpoints.contains(ResolvedEndpoint(address: destination, port: destinationPort)) { return true }
        // Only DHCP broadcasts; arbitrary unicast to port 67 is not an exception.
        guard u16(bytes, udp) == 68, destinationPort == 67,
              destination.bytes == [255, 255, 255, 255] else { return false }
        return validDHCPv4(bytes, start: udp + 8, end: start + totalLength)
    }

    private func allowsIPv6(_ bytes: UnsafeBufferPointer<UInt8>, start: Int) -> Bool {
        guard bytes.count - start >= 40 else { return false }
        let payloadLength = Int(u16(bytes, start + 4))
        guard payloadLength > 0, payloadLength <= bytes.count - start - 40 else { return false }
        let transport = start + 40
        let destination = IPAddress(bytes: Array(bytes[(start + 24)..<(start + 40)]), family: .ipv6)
        // Unsupported extension headers, including fragment and routing headers, fail closed.
        switch bytes[start + 6] {
        case 17:
            guard payloadLength >= 8, Int(u16(bytes, transport + 4)) == payloadLength else { return false }
            let destinationPort = u16(bytes, transport + 2)
            if destinationPort != 0 && endpoints.contains(ResolvedEndpoint(address: destination, port: destinationPort)) { return true }
            // DHCPv6 clients contact All_DHCP_Relay_Agents_and_Servers on the local link.
            guard u16(bytes, transport) == 546, destinationPort == 547, payloadLength >= 12,
                  destination.bytes == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2],
                  [1, 3, 4, 5, 6, 8, 9, 11].contains(bytes[transport + 8]) else { return false }
            let source = Array(bytes[(start + 8)..<(start + 24)])
            return source.allSatisfy { $0 == 0 } || isLinkLocal(source)
        case 58:
            return validNeighborDiscovery(bytes, start: start, payloadLength: payloadLength, destination: destination.bytes)
        default: return false
        }
    }

    private func validARP(_ bytes: UnsafeBufferPointer<UInt8>, start: Int) -> Bool {
        guard bytes.count - start >= 28 else { return false }
        return u16(bytes, start) == 1 && u16(bytes, start + 2) == 0x0800 &&
            bytes[start + 4] == 6 && bytes[start + 5] == 4 && [1, 2].contains(u16(bytes, start + 6))
    }

    private func validDHCPv4(_ bytes: UnsafeBufferPointer<UInt8>, start: Int, end: Int) -> Bool {
        guard end - start >= 244, bytes[start] == 1, bytes[start + 1] == 1, bytes[start + 2] == 6,
              Array(bytes[(start + 236)..<(start + 240)]) == [99, 130, 83, 99] else { return false }
        var option = start + 240
        var validType = false
        while option < end {
            let code = bytes[option]
            option += 1
            if code == 255 { return validType }
            if code == 0 { continue }
            guard option < end else { return false }
            let length = Int(bytes[option])
            option += 1
            guard length <= end - option else { return false }
            if code == 53 {
                guard !validType, length == 1, [1, 3, 8].contains(bytes[option]) else { return false }
                validType = true
            }
            option += length
        }
        return false
    }

    private func validNeighborDiscovery(_ bytes: UnsafeBufferPointer<UInt8>, start: Int,
                                        payloadLength: Int, destination: [UInt8]) -> Bool {
        let icmp = start + 40
        guard payloadLength >= 8, bytes[start + 7] == 255, bytes[icmp + 1] == 0 else { return false }
        let allRouters: [UInt8] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        let allNodes: [UInt8] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        switch bytes[icmp] {
        case 133: return destination == allRouters // Router solicitation, never advertisements.
        case 135, 136:
            guard payloadLength >= 24 else { return false }
            let target = Array(bytes[(icmp + 8)..<(icmp + 24)])
            guard target[0] != 0xff, target.contains(where: { $0 != 0 }) else { return false }
            if bytes[icmp] == 135 {
                let solicitedPrefix: [UInt8] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]
                return destination.prefix(13).elementsEqual(solicitedPrefix) || isLinkLocal(destination)
            }
            return destination == allNodes || isLinkLocal(destination)
        default: return false
        }
    }

    private func isLinkLocal(_ bytes: [UInt8]) -> Bool {
        bytes.count == 16 && bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80
    }

    private func u16(_ bytes: UnsafeBufferPointer<UInt8>, _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
}
