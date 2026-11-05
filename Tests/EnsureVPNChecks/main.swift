// Dependency-free checks for machines with Command Line Tools but without Xcode's Testing framework.
// The full Swift Testing suites live alongside this executable in EnsureVPNCoreTests.
import Foundation
import EnsureVPNCore
import Darwin

var failures = [String]()
var checkCount = 0
var scenarioCount = 0

func check(_ name: String, _ condition: @autoclosure () throws -> Bool) {
    checkCount += 1
    do {
        if try !condition() { failures.append(name) }
    } catch { failures.append("\(name): \(error)") }
}

func rejects(_ name: String, _ action: () throws -> Void) {
    checkCount += 1
    do { try action(); failures.append("\(name): expected rejection") } catch { }
}

func scenario(_ name: String, _ action: () throws -> Void) {
    scenarioCount += 1
    do { try action() } catch { failures.append("\(name): \(error)") }
}

func put16(_ bytes: inout [UInt8], _ at: Int, _ value: UInt16) {
    bytes[at] = UInt8(value >> 8)
    bytes[at + 1] = UInt8(value & 255)
}

func udp4(_ destination: String, port: UInt16, sourcePort: UInt16 = 50000, payload: [UInt8] = []) -> [UInt8] {
    var packet = [UInt8](repeating: 0, count: 28 + payload.count)
    packet[0] = 0x45; packet[8] = 64; packet[9] = 17
    put16(&packet, 2, UInt16(packet.count))
    packet.replaceSubrange(12..<16, with: [192, 0, 2, 10])
    packet.replaceSubrange(16..<20, with: IPAddress(destination)!.bytes)
    put16(&packet, 20, sourcePort); put16(&packet, 22, port)
    put16(&packet, 24, UInt16(8 + payload.count))
    packet.replaceSubrange(28..<packet.count, with: payload)
    return packet
}

func udp6(_ destination: String, port: UInt16, source: String = "2001:db8::2", sourcePort: UInt16 = 50000, payload: [UInt8] = []) -> [UInt8] {
    var packet = [UInt8](repeating: 0, count: 48 + payload.count)
    packet[0] = 0x60; packet[6] = 17; packet[7] = 64
    put16(&packet, 4, UInt16(8 + payload.count))
    packet.replaceSubrange(8..<24, with: IPAddress(source)!.bytes)
    packet.replaceSubrange(24..<40, with: IPAddress(destination)!.bytes)
    put16(&packet, 40, sourcePort); put16(&packet, 42, port)
    put16(&packet, 44, UInt16(8 + payload.count))
    packet.replaceSubrange(48..<packet.count, with: payload)
    return packet
}

func ethernet(_ payload: [UInt8], _ type: UInt16) -> [UInt8] {
    var header = [UInt8](repeating: 0, count: 14)
    put16(&header, 12, type)
    return header + payload
}

let policy = PacketPolicy(trustedInterfaceIndices: [42], endpoints: [
    ResolvedEndpoint(address: IPAddress("192.0.2.1")!, port: 51820),
    ResolvedEndpoint(address: IPAddress("2001:db8::1")!, port: 51820)
])

func allows(_ bytes: [UInt8], interface: UInt32 = 5, framing: PacketFraming = .rawIP) -> Bool {
    policy.allows(packet: Data(bytes), interfaceIndex: interface, isLoopback: false, outbound: true, framing: framing)
}

scenario("Public-only profile import") {
    let profile = try WireGuardConfiguration.parse("""
    [Interface]
    PrivateKey = PRIVATE_KEY_SENTINEL
    Address = 10.8.0.2/32, fd00:ABCD::2/128
    DNS = 10.8.0.1
    [Peer]
    PresharedKey = PRESHARED_KEY_SENTINEL
    Endpoint = VPN.Example.COM:51820 # Comment
    AllowedIPs = 0.0.0.0/0, ::/0
    """)
    check("Tunnel addresses canonicalized", profile.tunnelAddresses == ["10.8.0.2", "fd00:abcd::2"])
    check("Hostname canonicalized", profile.endpoints.first?.host == "vpn.example.com")
    check("Endpoint port retained", profile.endpoints.first?.port == 51820)
    let saved = try JSONEncoder().encode(profile)
    let text = String(decoding: saved, as: UTF8.self)
    check("Private key discarded", !text.contains("PRIVATE_KEY_SENTINEL"))
    check("Preshared key discarded", !text.contains("PRESHARED_KEY_SENTINEL"))
    check("Only required fields retained", !text.contains("DNS") && !text.contains("AllowedIPs"))
    check("Profile round trip", try JSONDecoder().decode(WireGuardConfiguration.self, from: saved) == profile)
}

scenario("Multi-peer and IPv6 import") {
    let profile = try WireGuardConfiguration.parse("[Interface]\nAddress = 10.0.0.2/32, 10.0.0.2/24\n[Peer]\nEndpoint = [2001:DB8::1]:443\n[Peer]\nEndpoint = 192.0.2.1:51820")
    check("Duplicate addresses merged", profile.tunnelAddresses == ["10.0.0.2"])
    check("Both peer endpoints retained", profile.endpoints.map(\.displayName) == ["[2001:db8::1]:443", "192.0.2.1:51820"])
}

scenario("Incomplete profiles rejected") {
    for invalid in ["", "[Interface]\nAddress = 10.0.0.2", "[Peer]\nEndpoint = 192.0.2.1:51820", "[Interface]\nAddress = 10.0.0.2\n[Peer]\n[Peer]\nEndpoint = 192.0.2.1:51820"] {
        rejects("Incomplete profile") { _ = try WireGuardConfiguration.parse(invalid) }
    }
}

scenario("Invalid tunnel addresses rejected") {
    for value in ["0.0.0.0/32", "127.0.0.1/8", "224.0.0.1/32", "::/128", "::1/128", "ff02::1/128", "10.0.0.2/33", "fd00::2/129", "10.0.0.2/", "10.0.0.2/32/1", "example.com/24", "10.0.0.2/32,", "fe80::1%en0/64"] {
        rejects("Invalid address \(value)") { _ = try WireGuardConfiguration.parse("[Interface]\nAddress = \(value)\n[Peer]\nEndpoint = 192.0.2.1:51820") }
    }
}

scenario("Invalid peer endpoints rejected") {
    for value in ["vpn.example.com", "vpn.example.com:0", "vpn.example.com:65536", "vpn.example.com:-1", "vpn.example.com:1.2", "vpn.example.com: 51820", "vpn..example.com:51820", "-vpn.example.com:51820", "[2001:db8::1]51820", "[example.com]:51820", "2001:db8::1:51820", "192.999.0.1:51820", "https://vpn.example.com:51820", "vpn.example.com:51820; echo hello", "vpn.example.com:１２３"] {
        check("Invalid endpoint \(value)", WireGuardEndpoint.parse(value) == nil)
    }
}

scenario("Profile size limits") {
    rejects("Oversized profile") { _ = try WireGuardConfiguration.parse(String(repeating: "s", count: 1_048_577)) }
    let addresses = (1...33).map { "10.8.0.\($0)/32" }.joined(separator: ", ")
    rejects("Too many addresses") { _ = try WireGuardConfiguration.parse("[Interface]\nAddress = \(addresses)\n[Peer]\nEndpoint = 192.0.2.1:51820") }
    let peers = String(repeating: "[Peer]\nEndpoint = 192.0.2.1:51820\n", count: 129)
    rejects("Too many endpoints") { _ = try WireGuardConfiguration.parse("[Interface]\nAddress = 10.8.0.2/32\n" + peers) }
}

scenario("IP address validation") {
    check("Canonical IPv6", IPAddress("2001:0db8:0000::0001")?.description == "2001:db8::1")
    check("Reject CIDR", IPAddress("192.0.2.1/32") == nil)
    check("Reject DNS", IPAddress("localhost") == nil)
    check("Reject embedded NUL", IPAddress("192.0.2.1\0ignored") == nil)
    check("Reject scoped addresses", IPAddress("fe80::1%en0") == nil)
    rejects("Invalid IP decoding") { _ = try JSONDecoder().decode(IPAddress.self, from: Data("\"not-an-ip\"".utf8)) }
}

scenario("Exact endpoint exceptions") {
    check("IPv4 WireGuard endpoint", allows(udp4("192.0.2.1", port: 51820)))
    check("IPv4 different IP blocked", !allows(udp4("192.0.2.2", port: 51820)))
    check("IPv4 different port blocked", !allows(udp4("192.0.2.1", port: 443)))
    check("DNS blocked", !allows(udp4("1.1.1.1", port: 53)))
    var tcp = udp4("192.0.2.1", port: 51820); tcp[9] = 6
    check("TCP blocked even for endpoint", !allows(tcp))
    check("IPv6 WireGuard endpoint", allows(udp6("2001:db8::1", port: 51820)))
    check("IPv6 different IP blocked", !allows(udp6("2001:db8::2", port: 51820)))
    check("IPv6 different port blocked", !allows(udp6("2001:db8::1", port: 443)))
}

scenario("Tunnel identity and disconnect") {
    var packet = udp4("1.1.1.1", port: 443)
    packet.replaceSubrange(12..<16, with: [10, 8, 0, 2])
    check("Spoofed source does not grant physical egress", !allows(packet))
    check("Trusted actual interface permits traffic", allows(packet, interface: 42))
    check("Unknown interface blocked", !allows(packet, interface: 0))
    let disconnected = PacketPolicy(endpoints: policy.endpoints)
    check("Removed tunnel blocked", !disconnected.allows(packet: Data(packet), interfaceIndex: 42, isLoopback: false, outbound: true))
    check("Physical fallback blocked", !disconnected.allows(packet: Data(packet), interfaceIndex: 5, isLoopback: false, outbound: true))
    check("Inbound allowed", policy.allows(packet: Data(packet), interfaceIndex: 5, isLoopback: false, outbound: false))
    check("Actual loopback allowed", policy.allows(packet: Data(packet), interfaceIndex: 1, isLoopback: true, outbound: true))
}

scenario("IPv4 fragments and options") {
    for bits: UInt16 in [0x2000, 0x0001, 0x2010, 0x8000] {
        var packet = udp4("192.0.2.1", port: 51820); put16(&packet, 6, bits)
        check("Fragment or reserved flags blocked", !allows(packet))
    }
    var packet = udp4("192.0.2.1", port: 51820); put16(&packet, 6, 0x4000)
    check("Do-not-fragment flag allowed", allows(packet))
    packet = udp4("192.0.2.1", port: 51820)
    packet.insert(contentsOf: [131, 4, 4, 0], at: 20); packet[0] = 0x46; put16(&packet, 2, UInt16(packet.count))
    check("Source routing option blocked", !allows(packet))
}

scenario("IPv6 extension headers") {
    for next: UInt8 in [0, 43, 44, 50, 51, 60, 59] {
        var packet = udp6("2001:db8::1", port: 51820); packet[6] = next
        check("Unsupported IPv6 extension \(next) blocked", !allows(packet))
    }
}

scenario("Truncation and length validation") {
    for packet in [udp4("192.0.2.1", port: 51820), udp6("2001:db8::1", port: 51820)] {
        for length in 0..<packet.count { check("Truncated packet at \(length) blocked", !allows(Array(packet.prefix(length)))) }
    }
    var packet = udp4("192.0.2.1", port: 51820); packet[0] = 0x4f
    check("Oversized IPv4 header blocked", !allows(packet))
    packet = udp4("192.0.2.1", port: 51820); put16(&packet, 24, 7)
    check("Undersized UDP header blocked", !allows(packet))
    var v6 = udp6("2001:db8::1", port: 51820); put16(&v6, 44, 100)
    check("Oversized UDP length blocked", !allows(v6))
    put16(&v6, 4, 0)
    check("IPv6 jumbogram blocked", !allows(v6))
}

scenario("Ethernet framing and VLAN") {
    var frame = ethernet(udp4("192.0.2.1", port: 51820), 0x0800); frame[0] = 0x45
    check("MAC resembling IP does not confuse Ethernet", allows(frame, framing: .ethernet))
    check("Ethernet not parsed as raw IP", !allows(frame))
    check("Unknown frame blocked", !allows(frame, framing: .unknown))
    put16(&frame, 12, 0x86dd)
    check("Mismatching EtherType blocked", !allows(frame, framing: .ethernet))
    put16(&frame, 12, 0x0800)
    frame.insert(contentsOf: [0x81, 0x00, 0, 1], at: 12)
    check("Single VLAN parsed", allows(frame, framing: .ethernet))
    frame.insert(contentsOf: [0x88, 0xa8, 0, 1], at: 12)
    check("Double VLAN parsed", allows(frame, framing: .ethernet))
    frame.insert(contentsOf: [0x81, 0x00, 0, 1], at: 12)
    check("Excess VLAN nesting blocked", !allows(frame, framing: .ethernet))
    for length in 0..<22 { check("Truncated VLAN blocked", !allows(Array(frame.prefix(length)), framing: .ethernet)) }
}

scenario("ARP exception") {
    var arp = [UInt8](repeating: 0, count: 28)
    put16(&arp, 0, 1); put16(&arp, 2, 0x0800); arp[4] = 6; arp[5] = 4; put16(&arp, 6, 1)
    check("ARP request allowed", allows(ethernet(arp, 0x0806), framing: .ethernet))
    put16(&arp, 6, 2)
    check("ARP reply allowed", allows(ethernet(arp, 0x0806), framing: .ethernet))
    put16(&arp, 6, 3)
    check("Invalid ARP operation blocked", !allows(ethernet(arp, 0x0806), framing: .ethernet))
    check("Truncated ARP blocked", !allows(ethernet(Array(arp.prefix(10)), 0x0806), framing: .ethernet))
}

scenario("DHCPv4 exception") {
    var body = [UInt8](repeating: 0, count: 240)
    body[0] = 1; body[1] = 1; body[2] = 6
    body.replaceSubrange(236..<240, with: [99, 130, 83, 99]); body += [53, 1, 1, 255]
    check("DHCP broadcast allowed", allows(udp4("255.255.255.255", port: 67, sourcePort: 68, payload: body)))
    check("Arbitrary DHCP unicast blocked", !allows(udp4("192.0.2.55", port: 67, sourcePort: 68, payload: body)))
    check("Arbitrary client port blocked", !allows(udp4("255.255.255.255", port: 67, sourcePort: 999, payload: body)))
    check("Invalid DHCP body blocked", !allows(udp4("255.255.255.255", port: 67, sourcePort: 68, payload: [1, 2, 3])))
    body[241] = 100
    check("Truncated DHCP option blocked", !allows(udp4("255.255.255.255", port: 67, sourcePort: 68, payload: body)))
}

scenario("DHCPv6 exception") {
    check("DHCPv6 local multicast allowed", allows(udp6("ff02::1:2", port: 547, source: "fe80::2", sourcePort: 546, payload: [1, 1, 2, 3])))
    check("DHCPv6 remote destination blocked", !allows(udp6("2001:db8::99", port: 547, source: "fe80::2", sourcePort: 546, payload: [1, 1, 2, 3])))
    check("DHCPv6 global source blocked", !allows(udp6("ff02::1:2", port: 547, source: "2001:db8::2", sourcePort: 546, payload: [1, 1, 2, 3])))
    check("DHCPv6 server message blocked", !allows(udp6("ff02::1:2", port: 547, source: "fe80::2", sourcePort: 546, payload: [2, 1, 2, 3])))
}

scenario("IPv6 neighbor discovery") {
    var packet = udp6("ff02::2", port: 0); packet[6] = 58; packet[7] = 255; packet[40] = 133; packet[41] = 0
    check("Router solicitation allowed", allows(packet))
    packet[7] = 64
    check("Routed solicitation blocked", !allows(packet))
    packet[7] = 255; packet[40] = 134
    check("Router advertisements blocked", !allows(packet))
    packet[40] = 128
    check("General ping blocked", !allows(packet))
}

scenario("Deterministic malformed-packet corpus") {
    let emptyPolicy = PacketPolicy()
    var seed: UInt64 = 0x123456789abcdef
    for length in 0..<512 {
        var packet = [UInt8]()
        for _ in 0..<length {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1
            packet.append(UInt8(truncatingIfNeeded: seed >> 32))
        }
        for framing in [PacketFraming.rawIP, .ethernet, .unknown] {
            check("Malformed packet \(length) blocked", !emptyPolicy.allows(packet: Data(packet), interfaceIndex: 5, isLoopback: false, outbound: true, framing: framing))
        }
    }
}

if failures.isEmpty {
    print("Passed \(scenarioCount) scenarios, \(checkCount) checks. No host networking was changed.")
} else {
    failures.forEach { print("FAIL: \($0)") }
    print("Failed \(failures.count) of \(checkCount) checks across \(scenarioCount) scenarios.")
    exit(1)
}
