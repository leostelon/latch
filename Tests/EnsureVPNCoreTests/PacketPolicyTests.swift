import Foundation
import Testing
@testable import EnsureVPNCore

@Suite("Fail closed egress policy")
struct PacketPolicyTests {
    let policy = PacketPolicy(trustedInterfaceIndices: [42], endpoints: [
        ResolvedEndpoint(address: IPAddress("192.0.2.1")!, port: 51820),
        ResolvedEndpoint(address: IPAddress("2001:db8::1")!, port: 51820)
    ])

    private func allows(_ bytes: [UInt8], interface: UInt32 = 5, framing: PacketFraming = .rawIP) -> Bool {
        policy.allows(packet: Data(bytes), interfaceIndex: interface, isLoopback: false, outbound: true, framing: framing)
    }

    @Test func permitsOnlyExactServerIPAndUDPPort() {
        #expect(allows(ipv4(destination: "192.0.2.1", destinationPort: 51820)))
        #expect(!allows(ipv4(destination: "192.0.2.2", destinationPort: 51820)))
        #expect(!allows(ipv4(destination: "192.0.2.1", destinationPort: 443)))
        #expect(!allows(ipv4(destination: "1.1.1.1", destinationPort: 53)))
        var tcp = ipv4(destination: "192.0.2.1", destinationPort: 51820)
        tcp[9] = 6
        #expect(!allows(tcp))
        #expect(allows(ipv6(destination: "2001:db8::1", destinationPort: 51820)))
        #expect(!allows(ipv6(destination: "2001:db8::2", destinationPort: 51820)))
        #expect(!allows(ipv6(destination: "2001:db8::1", destinationPort: 53)))
    }

    @Test func doesNotTrustSpoofedTunnelSourceAddress() {
        var packet = ipv4(destination: "1.1.1.1", destinationPort: 443)
        packet.replaceSubrange(12..<16, with: [10, 8, 0, 2])
        #expect(!allows(packet, interface: 5))
        #expect(allows(packet, interface: 42))
        #expect(!allows(packet, interface: 0))
    }

    @Test func trustedInterfacePermitsTunneledTrafficButDisconnectDoesNotPermitPhysicalTraffic() {
        let packet = ipv4(destination: "1.1.1.1", destinationPort: 443)
        #expect(allows(packet, interface: 42))
        #expect(!allows(packet, interface: 5))
        let disconnected = PacketPolicy(endpoints: policy.endpoints)
        #expect(!disconnected.allows(packet: Data(packet), interfaceIndex: 42, isLoopback: false, outbound: true))
        #expect(!disconnected.allows(packet: Data(packet), interfaceIndex: 5, isLoopback: false, outbound: true))
    }

    @Test func permitsIncomingAndActualLoopbackWithoutOpeningPhysicalEgress() {
        let packet = Data(ipv4(destination: "127.0.0.1", destinationPort: 443))
        #expect(policy.allows(packet: packet, interfaceIndex: 1, isLoopback: true, outbound: true))
        #expect(policy.allows(packet: packet, interfaceIndex: 5, isLoopback: false, outbound: false))
        #expect(!policy.allows(packet: packet, interfaceIndex: 5, isLoopback: false, outbound: true))
    }

    @Test func blocksAllIPv4FragmentsIncludingInitialFragment() {
        for bits: UInt16 in [0x2000, 0x0001, 0x2010, 0x8000] {
            var packet = ipv4(destination: "192.0.2.1", destinationPort: 51820)
            put16(&packet, 6, bits)
            #expect(!allows(packet))
        }
        var dontFragment = ipv4(destination: "192.0.2.1", destinationPort: 51820)
        put16(&dontFragment, 6, 0x4000)
        #expect(allows(dontFragment))
    }

    @Test func rejectsIPv6ExtensionFragmentAndRoutingHeaders() {
        for nextHeader: UInt8 in [0, 43, 44, 50, 51, 60, 59] {
            var packet = ipv6(destination: "2001:db8::1", destinationPort: 51820)
            packet[6] = nextHeader
            #expect(!allows(packet))
        }
    }

    @Test func rejectsIPv4OptionsIncludingSourceRouting() {
        var packet = ipv4(destination: "192.0.2.1", destinationPort: 51820)
        packet.insert(contentsOf: [131, 4, 4, 0], at: 20)
        packet[0] = 0x46
        put16(&packet, 2, UInt16(packet.count))
        #expect(!allows(packet))
    }

    @Test func truncatedHeadersAndInconsistentLengthsNeverPass() {
        for packet in [ipv4(destination: "192.0.2.1", destinationPort: 51820), ipv6(destination: "2001:db8::1", destinationPort: 51820)] {
            for length in 0..<packet.count { #expect(!allows(Array(packet.prefix(length)))) }
        }
        var packet = ipv4(destination: "192.0.2.1", destinationPort: 51820)
        packet[0] = 0x4f
        #expect(!allows(packet))
        packet = ipv4(destination: "192.0.2.1", destinationPort: 51820)
        put16(&packet, 24, 7)
        #expect(!allows(packet))
        var v6 = ipv6(destination: "2001:db8::1", destinationPort: 51820)
        put16(&v6, 44, 100)
        #expect(!allows(v6))
        put16(&v6, 4, 0)
        #expect(!allows(v6))
    }

    @Test func ethernetFramingDoesNotMistakeMACAddressForIPHeader() {
        var frame = ethernet(ipv4(destination: "192.0.2.1", destinationPort: 51820), etherType: 0x0800)
        frame[0] = 0x45
        #expect(allows(frame, framing: .ethernet))
        #expect(!allows(frame, framing: .rawIP))
        #expect(!allows(frame, framing: .unknown))
        put16(&frame, 12, 0x88b5)
        #expect(!allows(frame, framing: .ethernet))
        put16(&frame, 12, 0x86dd) // EtherType and IP version disagree.
        #expect(!allows(frame, framing: .ethernet))
    }

    @Test func ethernetVLANHasBoundedParsing() {
        var frame = ethernet(ipv4(destination: "192.0.2.1", destinationPort: 51820), etherType: 0x0800)
        frame.insert(contentsOf: [0x81, 0x00, 0, 1], at: 12)
        #expect(allows(frame, framing: .ethernet))
        frame.insert(contentsOf: [0x88, 0xa8, 0, 1], at: 12)
        #expect(allows(frame, framing: .ethernet))
        frame.insert(contentsOf: [0x81, 0x00, 0, 1], at: 12)
        #expect(!allows(frame, framing: .ethernet))
        for length in 0..<22 { #expect(!allows(Array(frame.prefix(length)), framing: .ethernet)) }
    }

    @Test func onlyWellFormedARPRequestsAndRepliesPass() {
        var arp = [UInt8](repeating: 0, count: 28)
        put16(&arp, 0, 1)
        put16(&arp, 2, 0x0800)
        arp[4] = 6
        arp[5] = 4
        put16(&arp, 6, 1)
        #expect(allows(ethernet(arp, etherType: 0x0806), framing: .ethernet))
        put16(&arp, 6, 2)
        #expect(allows(ethernet(arp, etherType: 0x0806), framing: .ethernet))
        put16(&arp, 6, 3)
        #expect(!allows(ethernet(arp, etherType: 0x0806), framing: .ethernet))
        #expect(!allows(ethernet(Array(arp.prefix(10)), etherType: 0x0806), framing: .ethernet))
    }

    @Test func DHCPExceptionIsLimitedToValidClientBroadcasts() {
        var bootp = [UInt8](repeating: 0, count: 240)
        bootp[0] = 1; bootp[1] = 1; bootp[2] = 6
        bootp.replaceSubrange(236..<240, with: [99, 130, 83, 99])
        bootp += [53, 1, 1, 255]
        #expect(allows(ipv4(destination: "255.255.255.255", sourcePort: 68, destinationPort: 67, payload: bootp)))
        #expect(!allows(ipv4(destination: "192.0.2.55", sourcePort: 68, destinationPort: 67, payload: bootp)))
        #expect(!allows(ipv4(destination: "255.255.255.255", sourcePort: 999, destinationPort: 67, payload: bootp)))
        #expect(!allows(ipv4(destination: "255.255.255.255", sourcePort: 68, destinationPort: 67, payload: [1, 2, 3])))
        bootp[241] = 100 // Truncated DHCP option must not read out of bounds.
        #expect(!allows(ipv4(destination: "255.255.255.255", sourcePort: 68, destinationPort: 67, payload: bootp)))
    }

    @Test func DHCPv6ExceptionStaysOnLocalLink() {
        let payload: [UInt8] = [1, 1, 2, 3]
        #expect(allows(ipv6(source: "fe80::2", destination: "ff02::1:2", sourcePort: 546, destinationPort: 547, payload: payload)))
        #expect(!allows(ipv6(source: "fe80::2", destination: "2001:db8::99", sourcePort: 546, destinationPort: 547, payload: payload)))
        #expect(!allows(ipv6(source: "2001:db8::2", destination: "ff02::1:2", sourcePort: 546, destinationPort: 547, payload: payload)))
        #expect(!allows(ipv6(source: "fe80::2", destination: "ff02::1:2", sourcePort: 546, destinationPort: 547, payload: [2, 1, 2, 3])))
    }

    @Test func neighborDiscoveryRequiresHopLimitAndLinkScope() {
        var solicitation = ipv6(destination: "ff02::2", destinationPort: 0)
        solicitation[6] = 58
        solicitation[7] = 255
        solicitation[40] = 133
        solicitation[41] = 0
        #expect(allows(solicitation))
        solicitation[7] = 64
        #expect(!allows(solicitation))
        solicitation[7] = 255
        solicitation[40] = 134 // A client does not need to advertise a router.
        #expect(!allows(solicitation))
        solicitation[40] = 128 // No general ICMP echo exception.
        #expect(!allows(solicitation))
    }

    @Test func malformedPacketCorpusCannotOpenDefaultPolicy() {
        let emptyPolicy = PacketPolicy()
        var seed: UInt64 = 0x123456789abcdef
        for length in 0..<512 {
            var packet = [UInt8]()
            for _ in 0..<length {
                seed = seed &* 6_364_136_223_846_793_005 &+ 1
                packet.append(UInt8(truncatingIfNeeded: seed >> 32))
            }
            for framing in [PacketFraming.rawIP, .ethernet, .unknown] {
                #expect(!emptyPolicy.allows(packet: Data(packet), interfaceIndex: 5, isLoopback: false, outbound: true, framing: framing))
            }
        }
    }
}

private func put16(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt16) {
    bytes[offset] = UInt8(value >> 8)
    bytes[offset + 1] = UInt8(value & 0xff)
}

private func ipv4(destination: String, sourcePort: UInt16 = 50000,
                  destinationPort: UInt16, payload: [UInt8] = []) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: 28 + payload.count)
    result[0] = 0x45
    put16(&result, 2, UInt16(result.count))
    result[8] = 64
    result[9] = 17
    result.replaceSubrange(12..<16, with: [192, 0, 2, 10])
    result.replaceSubrange(16..<20, with: IPAddress(destination)!.bytes)
    put16(&result, 20, sourcePort)
    put16(&result, 22, destinationPort)
    put16(&result, 24, UInt16(8 + payload.count))
    result.replaceSubrange(28..<result.count, with: payload)
    return result
}

private func ipv6(source: String = "2001:db8::2", destination: String, sourcePort: UInt16 = 50000,
                  destinationPort: UInt16, payload: [UInt8] = []) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: 48 + payload.count)
    result[0] = 0x60
    put16(&result, 4, UInt16(8 + payload.count))
    result[6] = 17
    result[7] = 64
    result.replaceSubrange(8..<24, with: IPAddress(source)!.bytes)
    result.replaceSubrange(24..<40, with: IPAddress(destination)!.bytes)
    put16(&result, 40, sourcePort)
    put16(&result, 42, destinationPort)
    put16(&result, 44, UInt16(8 + payload.count))
    result.replaceSubrange(48..<result.count, with: payload)
    return result
}

private func ethernet(_ payload: [UInt8], etherType: UInt16) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: 14)
    put16(&result, 12, etherType)
    return result + payload
}
