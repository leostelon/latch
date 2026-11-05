import Darwin
import Foundation
import EnsureVPNCore

var count = 0
var failures = [String]()
func check(_ name: String, _ value: @autoclosure () -> Bool) {
    count += 1
    if !value() { failures.append(name) }
}
func rejects(_ name: String, _ operation: () throws -> Void) {
    count += 1
    do { try operation(); failures.append(name) } catch { }
}
func accepts(_ name: String, _ operation: () throws -> Void) {
    count += 1
    do { try operation() } catch { failures.append("\(name): \(error.localizedDescription)") }
}

let endpoint4 = ResolvedEndpoint(address: IPAddress("192.0.2.1")!, port: 51820)
let endpoint6 = ResolvedEndpoint(address: IPAddress("2001:db8::1")!, port: 51820)
let configuration = try PFConfiguration(tunnelAddresses: ["10.8.0.2", "fd00::2"], endpoints: [endpoint4, endpoint6])
let data = try JSONEncoder().encode(configuration)
let decodedConfiguration = try JSONDecoder().decode(PFConfiguration.self, from: data)
check("Configuration JSON round trip", decodedConfiguration == configuration)
check("Wire format numeric endpoint", String(data: data, encoding: .utf8)!.contains("192.0.2.1"))
let deduplicated = try PFConfiguration(tunnelAddresses: ["fd00:0::2", "fd00::2", "10.8.0.2"], endpoints: [endpoint4, endpoint4])
check("Tunnel addresses canonicalized and deduplicated", deduplicated.tunnelAddresses == ["10.8.0.2", "fd00::2"])
check("Endpoints deduplicated", deduplicated.endpoints == [endpoint4])

for bad in ["10.8.0.2/8", "10.8.0.2\npass all", "hostname.example", "fd00::2%utun4", "0.0.0.0", "127.0.0.1", "224.1.2.3", "::", "::1", "ff02::1", "192.0.2.1\u{0}"] {
    rejects("Reject unsafe tunnel address") { _ = try PFConfiguration(tunnelAddresses: [bad], endpoints: [endpoint4]) }
}
rejects("Reject zero endpoint port") {
    _ = try PFConfiguration(tunnelAddresses: ["10.8.0.2"], endpoints: [.init(address: endpoint4.address, port: 0)])
}
rejects("Reject multicast endpoint") {
    _ = try PFConfiguration(tunnelAddresses: ["10.8.0.2"], endpoints: [.init(address: IPAddress("ff02::1")!, port: 51820)])
}
rejects("Reject empty tunnel list") { _ = try PFConfiguration(tunnelAddresses: [], endpoints: [endpoint4]) }
rejects("Reject empty endpoint list") { _ = try PFConfiguration(tunnelAddresses: ["10.8.0.2"], endpoints: []) }
rejects("Reject excessive tunnel list") { _ = try PFConfiguration(tunnelAddresses: Array(repeating: "10.8.0.2", count: 33), endpoints: [endpoint4]) }
rejects("Reject excessive endpoint list") { _ = try PFConfiguration(tunnelAddresses: ["10.8.0.2"], endpoints: Array(repeating: endpoint4, count: 129)) }
for badJSON in [
    #"{"tunnelAddresses":["10.8.0.2"],"endpoints":[{"address":"192.0.2.1","port":0}]}"#,
    #"{"tunnelAddresses":["10.8.0.2"],"endpoints":[{"address":"192.0.2.1","port":65536}]}"#,
    #"{"tunnelAddresses":["10.8.0.2"],"endpoints":[{"address":"vpn.example.com","port":51820}]}"#
] {
    rejects("Untrusted JSON validates at decode") { _ = try JSONDecoder().decode(PFConfiguration.self, from: Data(badJSON.utf8)) }
}

let connected = try PFPolicy.rules(configuration: configuration, trustedInterfaces: ["utun12"])
let disconnected = try PFPolicy.rules(configuration: configuration, trustedInterfaces: [])
check("Disconnected rules trust no tunnel", !disconnected.contains("utun"))
check("No wildcard tunnel allowance", !connected.contains("on utun ") && !connected.contains("utun*"))
check("Tunnel allowance bound to interface and source", connected.contains("pass out quick on utun12 inet from 10.8.0.2/32 to any no state"))
check("IPv6 tunnel allowance bound to source", connected.contains("pass out quick on utun12 inet6 from fd00::2/128 to any no state"))
check("Endpoint allowance limited to UDP exact IP and port", connected.contains("proto udp from any to 192.0.2.1/32 port = 51820 no state"))
check("IPv6 endpoint allowance exact", connected.contains("proto udp from any to 2001:db8::1/128 port = 51820 no state"))
check("No DNS exception", !connected.contains("port = 53 "))
check("No blanket LAN exception", !connected.contains("10.0.0.0/8") && !connected.contains("192.168.0.0/16"))
check("Every pass is stateless and quick", connected.split(separator: "\n").filter { $0.hasPrefix("pass ") }.allSatisfy { $0.contains(" quick ") && $0.hasSuffix(" no state") })
check("No broad inbound pass", !connected.contains("pass in quick all"))
check("Terminal in and out denial", connected.hasSuffix("block drop in quick all\nblock drop out quick all\n"))
check("Fragments explicitly blocked outside tunnel", connected.contains("block drop quick all fragment"))
for bad in ["utun", "en0", "utun*", "utun2\npass all", "utun２", "utun1234567890123", "!utun3", "utun3:network"] {
    rejects("Reject injected or non-tunnel interface") { _ = try PFPolicy.rules(configuration: configuration, trustedInterfaces: [bad]) }
}

let root = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
accepts("Stock root rules") { try PFPolicy.validateRootRules(root) }
accepts("Stock root without normalization hook") { try PFPolicy.validateRootRules("anchor \"com.apple/*\" all") }
for bad in ["", "anchor \"/*\" all", "anchor \"com.apple/*\" out all", root + "pass quick all", root + "block all", root + "anchor \"custom/*\" all", root + "anchor \"com.apple/*\" all"] {
    rejects("Reject missing/conditional/foreign root rules") { try PFPolicy.validateRootRules(bad) }
}
accepts("Empty foreign anchor scaffolding") { try PFPolicy.validateForeignRules("anchor \"250.ApplicationFirewall/*\" all {\n}\n") }
accepts("Empty foreign translation scaffolding") { try PFPolicy.validateForeignRules("nat-anchor \"child/*\" all\nrdr-anchor \"child/*\" all") }
for rule in ["pass in all", "pass in quick all no state", "block all", "anchor \"x\" all { pass all }", "match out all", "nat on en0 from 10.0.0.0/8 to any -> (en0)", "rdr on en0 proto tcp to any port 80 -> 127.0.0.1"] {
    rejects("Reject foreign state, filter, or translation rules") { try PFPolicy.validateForeignRules(rule) }
}
accepts("Stock translation hooks") { try PFPolicy.validateRootTranslationRules("nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all") }
accepts("No translation hooks") { try PFPolicy.validateRootTranslationRules("") }
rejects("Reject active root NAT") { try PFPolicy.validateRootTranslationRules("nat on en0 from any to any -> (en0)") }
rejects("Reject foreign translation anchor") { try PFPolicy.validateRootTranslationRules("nat-anchor \"custom/*\" all") }
accepts("Loopback skip allowed") { try PFPolicy.validateInterfaces("lo0 (skip)\n en0\n utun12") }
for name in ["en0", "utun12", "all", "lo1"] {
    rejects("Reject skipped non-loopback interface") { try PFPolicy.validateInterfaces("lo0\n\(name) (skip)") }
}
for report in ["", "en0", "lo0\nunknown: changed output", "lo0\n[unexpected skip format]"] {
    rejects("Reject empty, incomplete, or unrecognized interface report") { try PFPolicy.validateInterfaces(report) }
}
check("Canonical comparison preserves rule order", PFPolicy.normalizedRules("pass   quick on lo0 all no state\n\nblock drop out quick all") == ["pass quick on lo0 all no state", "block drop out quick all"])

// Saved connection migration and aggregation must not widen the helper's policy.
let legacyJSON = Data(#"{"name":"Home","tunnelAddresses":["10.8.0.2","fd00:0::2"],"endpoints":[{"address":"192.0.2.1","port":51820}],"importedAt":1234,"usesHostnameEndpoint":true,"PrivateKey":"do-not-save-this-key"}"#.utf8)
let migrated = try SavedVPNProfiles.decode(current: nil, legacy: legacyJSON)
check("Legacy single connection migrates", migrated.count == 1 && migrated[0].name == "Home")
check("Legacy addresses canonicalized", migrated[0].tunnelAddresses == ["10.8.0.2", "fd00::2"])
check("Legacy public metadata preserved", migrated[0].importedAt == Date(timeIntervalSinceReferenceDate: 1234) && migrated[0].usesHostnameEndpoint == true)
let migratedData = try SavedVPNProfiles.encode(migrated)
check("Profile encoding retains no unknown key material", !String(decoding: migratedData, as: UTF8.self).contains("PrivateKey") && !String(decoding: migratedData, as: UTF8.self).contains("do-not-save-this-key"))
let reloaded = try SavedVPNProfiles.decode(current: migratedData, legacy: legacyJSON)
check("Migrated identity remains stable after persistence", reloaded == migrated)
let noSavedProfiles = try SavedVPNProfiles.decode(current: nil, legacy: nil)
let intentionallyEmptyProfiles = try SavedVPNProfiles.decode(current: Data("[]".utf8), legacy: legacyJSON)
check("No saved configuration decodes empty", noSavedProfiles.isEmpty)
check("Empty current store does not resurrect legacy connection", intentionallyEmptyProfiles.isEmpty)
rejects("Corrupt current store cannot fall back to stale legacy") {
    _ = try SavedVPNProfiles.decode(current: Data("broken".utf8), legacy: legacyJSON)
}
rejects("Oversized current profile store rejected") {
    _ = try SavedVPNProfiles.decode(current: Data(repeating: 32, count: 2_097_153), legacy: nil)
}
rejects("Oversized legacy profile rejected") {
    _ = try SavedVPNProfiles.decode(current: nil, legacy: Data(repeating: 32, count: 2_097_153))
}
let withoutHostnameFlag = try SavedVPNProfiles.decode(current: nil, legacy: Data(#"{"name":"Old","tunnelAddresses":["10.8.0.2"],"endpoints":[{"address":"192.0.2.1","port":51820}],"importedAt":0}"#.utf8))
check("Old optional hostname field migrates", withoutHostnameFlag[0].usesHostnameEndpoint == nil)
rejects("Legacy malformed endpoints rejected") {
    _ = try SavedVPNProfiles.decode(current: nil, legacy: Data(#"{"name":"Old","tunnelAddresses":["10.8.0.2"],"endpoints":[{"address":"192.0.2.1","port":0}],"importedAt":0}"#.utf8))
}

let home = try SavedVPNProfile(name: "Home", tunnelAddresses: ["10.8.0.2"], endpoints: [endpoint4])
let office = try SavedVPNProfile(name: "Home", tunnelAddresses: ["10.9.0.2"], endpoints: [endpoint4, endpoint6])
let bothProfiles = try SavedVPNProfiles.appending(imported: [office], to: [home])
check("Distinct connections with the same name both retained", bothProfiles.count == 2 && bothProfiles[0].id == home.id && bothProfiles[1].id == office.id)
let combined = try SavedVPNProfiles.combinedConfiguration(bothProfiles)
check("Multiple profiles combine exact tunnel addresses", combined.tunnelAddresses == ["10.8.0.2", "10.9.0.2"])
check("Shared endpoints are deduplicated", Set(combined.endpoints) == Set([endpoint4, endpoint6]))
let homeDuplicate = try SavedVPNProfile(name: "Renamed file", tunnelAddresses: ["10.8.0.2"], endpoints: [endpoint4, endpoint4])
let noDuplicate = try SavedVPNProfiles.appending(imported: [homeDuplicate, homeDuplicate], to: bothProfiles)
check("Duplicate configurations preserve existing identity and metadata", noDuplicate == bothProfiles)
let removedOffice = try SavedVPNProfiles.combinedConfiguration(bothProfiles.filter { $0.id != office.id })
check("Removing a profile removes its unique addresses and endpoints", removedOffice.tunnelAddresses == home.tunnelAddresses && removedOffice.endpoints == home.endpoints)
let removedHome = try SavedVPNProfiles.combinedConfiguration(bothProfiles.filter { $0.id != home.id })
check("Removing a profile retains exceptions shared by another", Set(removedHome.endpoints) == Set([endpoint4, endpoint6]))
let emptyRoundTrip = try SavedVPNProfiles.decode(current: SavedVPNProfiles.encode([]), legacy: nil)
check("Empty list persists", emptyRoundTrip.isEmpty)
rejects("Empty connection list cannot enable the helper") { _ = try SavedVPNProfiles.combinedConfiguration([]) }
rejects("Duplicate saved identities rejected on encode") { _ = try SavedVPNProfiles.encode([home, home]) }
rejects("Duplicate saved identities rejected on decode") {
    _ = try SavedVPNProfiles.decode(current: JSONEncoder().encode([home, home]), legacy: nil)
}
let identityCollision = try SavedVPNProfile(id: home.id, name: "Other", tunnelAddresses: office.tunnelAddresses, endpoints: office.endpoints)
rejects("Different imported configuration cannot reuse existing identity") {
    _ = try SavedVPNProfiles.appending(imported: [identityCollision], to: [home])
}
rejects("Invalid profile address rejected before persistence") {
    _ = try SavedVPNProfile(name: "Bad", tunnelAddresses: ["10.8.0.2\npass all"], endpoints: [endpoint4])
}

let manySharedAddresses = try (1...64).map { index in
    try SavedVPNProfile(name: "Server \(index)", tunnelAddresses: ["10.8.0.2"], endpoints: [
        ResolvedEndpoint(address: IPAddress("192.0.2.\(index)")!, port: 51820)
    ])
}
let combinedShared = try SavedVPNProfiles.combinedConfiguration(manySharedAddresses)
check("Limits count unique addresses across saved connections", combinedShared.tunnelAddresses.count == 1 && combinedShared.endpoints.count == 64)
rejects("More than 64 saved connections rejected") { _ = try SavedVPNProfiles.encode(manySharedAddresses + [office]) }
let manyUniqueAddresses = try (1...33).map { index in
    try SavedVPNProfile(name: "Tunnel \(index)", tunnelAddresses: ["10.8.0.\(index)"], endpoints: [endpoint4])
}
rejects("Combined address limit enforced before saving") { _ = try SavedVPNProfiles.encode(manyUniqueAddresses) }
let firstEndpoints = (1...128).map { ResolvedEndpoint(address: IPAddress("192.0.2.\($0)")!, port: 51820) }
let fullProfile = try SavedVPNProfile(name: "Full", tunnelAddresses: ["10.8.0.2"], endpoints: firstEndpoints)
let extraProfile = try SavedVPNProfile(name: "Extra", tunnelAddresses: ["10.8.0.2"], endpoints: [endpoint6])
rejects("Combined endpoint limit enforced before appending") {
    _ = try SavedVPNProfiles.appending(imported: [extraProfile], to: [fullProfile])
}
let multiProfileRules = try PFPolicy.rules(configuration: combined, trustedInterfaces: [])
check("Every saved server receives an exact UDP exception", multiProfileRules.contains("to 192.0.2.1/32 port = 51820") && multiProfileRules.contains("to 2001:db8::1/128 port = 51820"))
check("Multiple saved connections retain default denial", multiProfileRules.hasSuffix("block drop in quick all\nblock drop out quick all\n"))

// Exercise Apple's actual PF parser without loading rules or opening /dev/pf.
// -n means no changes. This remains safe without administrator privileges.
let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ensure-vpn-pfchecks-\(UUID().uuidString)")
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
defer { try? FileManager.default.removeItem(at: directory) }
for (name, rules) in [("connected", connected), ("disconnected", disconnected), ("multiple-profiles", multiProfileRules)] {
    let path = directory.appendingPathComponent(name + ".pf")
    try Data(rules.utf8).write(to: path)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
    process.arguments = ["-n", "-v", "-a", PFPolicy.anchor, "-f", path.path]
    let output = Pipe(), errors = Pipe()
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    let stdout = output.fileHandleForReading.readDataToEndOfFile()
    let stderr = errors.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    check("Apple PF parser accepts \(name) rules", process.terminationStatus == 0)
    if process.terminationStatus != 0 { print(String(data: stderr, encoding: .utf8) ?? "PF parser failed") }
    let canonical = PFPolicy.normalizedRules(String(data: stdout, encoding: .utf8) ?? "")
    check("PF canonical output includes terminal denial", Array(canonical.suffix(2)) == ["block drop in quick all", "block drop out quick all"])
    check("PF canonical passes stay stateless", canonical.filter { $0.hasPrefix("pass ") }.allSatisfy { $0.hasSuffix("no state") })
}

if failures.isEmpty {
    print("Passed \(count) PF checks, including Apple's connected/disconnected rule parser. No firewall rules were changed.")
} else {
    failures.forEach { print("FAIL: \($0)") }
    exit(1)
}
