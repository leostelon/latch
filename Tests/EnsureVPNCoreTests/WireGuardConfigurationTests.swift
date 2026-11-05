import Foundation
import Testing
@testable import EnsureVPNCore

@Suite("WireGuard profile import")
struct WireGuardConfigurationTests {
    @Test func importsOnlyPublicRoutingInformation() throws {
        let profile = try WireGuardConfiguration.parse("""
        # Exported WireGuard profile
        [Interface]
        PrivateKey = DO_NOT_PERSIST_THIS_PRIVATE_KEY
        Address = 10.8.0.2/32, fd00:ABCD::2/128
        DNS = 10.8.0.1

        [Peer]
        PublicKey = irrelevant-public-key
        PresharedKey = DO_NOT_PERSIST_THIS_PRESHARED_KEY
        Endpoint = VPN.Example.COM:51820 # Public server
        AllowedIPs = 0.0.0.0/0, ::/0
        """)
        #expect(profile.tunnelAddresses == ["10.8.0.2", "fd00:abcd::2"])
        #expect(profile.endpoints == [WireGuardEndpoint(host: "vpn.example.com", port: 51820)])
        let saved = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
        #expect(!saved.contains("PRIVATE_KEY"))
        #expect(!saved.contains("PRESHARED_KEY"))
        #expect(!saved.contains("PrivateKey"))
        #expect(!saved.contains("DNS"))
        #expect(try JSONDecoder().decode(WireGuardConfiguration.self, from: Data(saved.utf8)) == profile)
    }

    @Test func importsIPv6EndpointAndMultiplePeers() throws {
        let profile = try WireGuardConfiguration.parse("""
        [Interface]
        Address = 10.0.0.2/24
        Address = 10.0.0.2/32, fd00::2/64
        [Peer]
        Endpoint = [2001:DB8::1]:443
        [Peer]
        Endpoint = 192.0.2.2:51820
        """)
        #expect(profile.tunnelAddresses == ["10.0.0.2", "fd00::2"])
        #expect(profile.endpoints.map(\.displayName) == ["[2001:db8::1]:443", "192.0.2.2:51820"])
    }

    @Test(arguments: ["", "[Interface]\nAddress = 10.0.0.2/32", "[Peer]\nEndpoint = vpn.example.com:51820", "Address = 10.0.0.2", "[Interface]\nAddress = 10.0.0.2\n[Peer]\n[Peer]\nEndpoint = 192.0.2.1:51820"])
    func rejectsIncompleteStructure(_ text: String) {
        #expect(throws: ConfigurationError.self) { try WireGuardConfiguration.parse(text) }
    }

    @Test(arguments: ["0.0.0.0/32", "127.0.0.1/8", "224.0.0.1/32", "::/128", "::1/128", "ff02::1/128", "10.0.0.2/33", "fd00::2/129", "10.0.0.2/", "10.0.0.2/32/1", "example.com/24", "10.0.0.2/32,", "fe80::1%en0/64"])
    func rejectsInvalidTunnelAddresses(_ address: String) {
        #expect(throws: ConfigurationError.self) {
            try WireGuardConfiguration.parse("[Interface]\nAddress = \(address)\n[Peer]\nEndpoint = 192.0.2.1:51820")
        }
    }

    @Test(arguments: ["vpn.example.com", "vpn.example.com:0", "vpn.example.com:65536", "vpn.example.com:-1", "vpn.example.com:1.2", "vpn.example.com: 51820", "vpn..example.com:51820", "-vpn.example.com:51820", "[2001:db8::1]51820", "[example.com]:51820", "2001:db8::1:51820", "192.999.0.1:51820", "https://vpn.example.com:51820", "vpn.example.com:51820; echo hello", "vpn.example.com:１２３"])
    func rejectsMalformedEndpoints(_ endpoint: String) {
        #expect(WireGuardEndpoint.parse(endpoint) == nil)
    }

    @Test func oversizedFileFailsWithoutQuotingSecrets() {
        #expect(throws: ConfigurationError.fileTooLarge) {
            try WireGuardConfiguration.parse(String(repeating: "SENSITIVE", count: 150_000))
        }
        let message = ConfigurationError.invalidStructure(3).localizedDescription
        #expect(!message.contains("SENSITIVE"))
    }

    @Test func boundsConfigurationToProviderLimits() {
        let addresses = (1...33).map { "10.8.0.\($0)/32" }.joined(separator: ", ")
        #expect(throws: ConfigurationError.tooManyAddresses) {
            try WireGuardConfiguration.parse("[Interface]\nAddress = \(addresses)\n[Peer]\nEndpoint = 192.0.2.1:51820")
        }
        let peers = String(repeating: "[Peer]\nEndpoint = 192.0.2.1:51820\n", count: 129)
        #expect(throws: ConfigurationError.tooManyEndpoints) {
            try WireGuardConfiguration.parse("[Interface]\nAddress = 10.8.0.2/32\n" + peers)
        }
    }

    @Test func ipAddressCanonicalizationAndDecoding() throws {
        #expect(IPAddress("2001:0db8:0000::0001")?.description == "2001:db8::1")
        #expect(IPAddress("192.0.2.1")?.bytes == [192, 0, 2, 1])
        #expect(IPAddress("192.0.2.1/32") == nil)
        #expect(IPAddress("localhost") == nil)
        #expect(IPAddress("192.0.2.1\0ignored") == nil)
        #expect(IPAddress("fe80::1%en0") == nil)
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(IPAddress.self, from: Data("\"not-an-ip\"".utf8))
        }
    }
}
