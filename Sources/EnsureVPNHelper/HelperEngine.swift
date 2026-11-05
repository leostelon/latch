import Foundation
import Darwin
import MachO
import EnsureVPNCore

struct HelperStatus: Codable {
    var schemaVersion = 1
    var helperVersion = 1
    var enabled: Bool
    var verified: Bool
    var updatedAt = Date().timeIntervalSince1970
    var message: String
    var tunnelInterfaces: [String] = []
}

private struct SavedPolicy: Codable {
    var configuration: PFConfiguration
    var desiredEnabled: Bool = true
    var token: String?
    var tokenBoot: String?
    var stateFlushBoot: String?
}

final class HelperEngine {
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let service = "system/dev.ensurevpn.helper"
    private let stateName = "policy.json"

    private func pf(_ arguments: [String], rules: String? = nil, requireSuccess: Bool = true) throws -> CommandResult {
        try CommandRunner.run("/sbin/pfctl", arguments, input: rules.map { Data($0.utf8) }, requireSuccess: requireSuccess)
    }

    func enable(_ input: String) throws -> HelperStatus {
        guard input.utf8.count <= 131_072, let data = Data(base64Encoded: input) else {
            throw HelperFailure("The VPN policy is not valid base64 JSON.")
        }
        let configuration = try decoder.decode(PFConfiguration.self, from: data).validated()
        return try SecureStore.locked {
            try preflight()
            let existingPolicy = try readPolicy()
            if existingPolicy == nil {
                guard PFPolicy.normalizedRules(try pf(["-a", PFPolicy.anchor, "-sr"]).output).isEmpty else {
                    throw HelperFailure("The Latch anchor already contains rules without this helper's ownership record. Refusing to replace them.")
                }
            }
            if let existing = existingPolicy, existing.desiredEnabled {
                // Changing the active tunnel in place would need another global state reset.
                // Require an explicit disable so that interruption is always user initiated.
                guard existing.configuration == configuration else {
                    throw HelperFailure("Disable the network block before changing its tunnel or server addresses.")
                }
            }
            try installHelper()
            var policy = existingPolicy ?? SavedPolicy(configuration: configuration)
            guard policy.desiredEnabled else { throw HelperFailure("A previous disable needs to finish. Retry Disable before enabling protection.") }
            try savePolicy(policy)
            do {
                let status = try apply(&policy, forceStateReset: policy.stateFlushBoot == nil)
                try startWatcher()
                return try publish(status)
            } catch {
                _ = try? startWatcher()
                _ = try? publish(.init(enabled: true, verified: false,
                    message: "Setup did not finish: \(error.localizedDescription) Use Disable to recover. Existing rules may remain active."))
                throw error
            }
        }
    }

    func disable() throws -> HelperStatus {
        try SecureStore.locked {
            var saved = try readPolicy()
            if var value = saved {
                // Journal the user's intent before touching PF. A crash mid-disable
                // must not cause launchd to silently re-arm the previous policy.
                value.desiredEnabled = false
                try savePolicy(value)
                saved = value
            }
            let currentRules = try pf(["-a", PFPolicy.anchor, "-sr"]).output
            if !PFPolicy.normalizedRules(currentRules).isEmpty {
                // Without our protected policy record we cannot establish ownership.
                guard saved != nil else {
                    throw HelperFailure("The Latch anchor contains rules but its ownership record is missing. Refusing to remove unknown rules; inspect PF manually.")
                }
                _ = try pf(["-o", "none", "-a", PFPolicy.anchor, "-f", "-"], rules: "")
                guard PFPolicy.normalizedRules(try pf(["-a", PFPolicy.anchor, "-sr"]).output).isEmpty else {
                    throw HelperFailure("Could not verify removal of the Latch rules.")
                }
            }
            // Only our enable reference is released. Never globally disable PF.
            let currentBoot = try bootID()
            if let token = saved?.token, saved?.tokenBoot == currentBoot {
                let release = try pf(["-X", token], requireSuccess: false)
                let alreadyReleased = (release.error + release.output).lowercased().contains("token invalid")
                    || (release.error + release.output).lowercased().contains("invalid token")
                if release.status != 0 && !alreadyReleased {
                    // Rules are removed, but retain the token record for a retry.
                    _ = try? publish(.init(enabled: false, verified: false,
                        message: "The block rules were removed, but PF's enable reference could not be released. Retry Disable. Other firewall settings were preserved."))
                    throw HelperFailure("Block rules removed, but the PF enable reference could not be released. Retry Disable.")
                }
            }
            saved = nil
            try SecureStore.remove(stateName)
            return try publish(.init(enabled: false, verified: false,
                message: "Latch's block is off. Normal network routing and other firewall settings apply."))
        }
    }

    func status() throws -> HelperStatus {
        try SecureStore.locked {
            guard let policy = try readPolicy() else {
                let rules = try pf(["-a", PFPolicy.anchor, "-sr"]).output
                guard PFPolicy.normalizedRules(rules).isEmpty else {
                    throw HelperFailure("Rules remain in Latch's anchor without its ownership record. Inspect PF before relying on the displayed state.")
                }
                return try publish(.init(enabled: false, verified: false, message: "The network block is off."))
            }
            guard policy.desiredEnabled else {
                return try publish(.init(enabled: true, verified: false, message: "Disabling did not finish. Retry Disable to remove remaining rules and release PF ownership."))
            }
            let interfaces = try trustedInterfaces(for: policy.configuration)
            do {
                try verify(configuration: policy.configuration, interfaces: interfaces)
                guard policy.stateFlushBoot == (try bootID()) else {
                    throw HelperFailure("The initial connection-state reset has not been verified for this boot.")
                }
                return try publish(.init(enabled: true, verified: true, message: verifiedMessage(interfaces), tunnelInterfaces: interfaces))
            } catch {
                return try publish(.init(enabled: true, verified: false, message: error.localizedDescription, tunnelInterfaces: interfaces))
            }
        }
    }

    /// Read-only PF inspection. It does not load rules, flush states, or enable PF.
    func preflight() throws {
        try PFPolicy.validateRootRules(try pf(["-sr"]).output)
        try PFPolicy.validateInterfaces(try pf(["-v", "-s", "Interfaces"]).output)
        try PFPolicy.validateRootTranslationRules(try pf(["-sn"]).output)
        var visited = Set<String>()
        try inspectAnchors(parent: "", depth: 0, visited: &visited)
    }

    func watch() {
        while true {
            do {
                try SecureStore.locked {
                    guard var policy = try readPolicy() else {
                        let actual = try pf(["-a", PFPolicy.anchor, "-sr"]).output
                        let empty = PFPolicy.normalizedRules(actual).isEmpty
                        _ = try publish(.init(enabled: false, verified: false,
                            message: empty ? "The network block is off." : "Unexpected rules remain in Latch's anchor. Inspect PF before relying on its state."))
                        return
                    }
                    guard policy.desiredEnabled else {
                        _ = try publish(.init(enabled: true, verified: false,
                            message: "Disabling did not finish. Retry Disable; the helper will not re-enable protection."))
                        return
                    }
                    do {
                        let status = try apply(&policy, forceStateReset: false)
                        _ = try publish(status)
                    } catch {
                        // Do not clear protection on any inspection/update failure.
                        _ = try publish(.init(enabled: true, verified: false,
                            message: "Protection could not be verified: \(error.localizedDescription) Existing block rules remain installed when possible."))
                    }
                }
            } catch {
                // If storage itself is unsafe, don't overwrite it. The last heartbeat
                // expires in the UI, which must display an unknown protection state.
                fputs("Latch helper: \(error.localizedDescription)\n", stderr)
            }
            Thread.sleep(forTimeInterval: 2)
        }
    }

    private func apply(_ policy: inout SavedPolicy, forceStateReset: Bool) throws -> HelperStatus {
        try preflight()
        let interfaces = try trustedInterfaces(for: policy.configuration)
        let rules = try PFPolicy.rules(configuration: policy.configuration, trustedInterfaces: interfaces)
        let expected = try canonicalRules(rules)
        let actual = PFPolicy.normalizedRules(try pf(["-a", PFPolicy.anchor, "-sr"]).output)
        if actual != expected {
            _ = try pf(["-o", "none", "-a", PFPolicy.anchor, "-f", "-"], rules: rules)
        }
        let boot = try bootID()
        let isPFEnabled = try pf(["-s", "info"]).output.contains("Status: Enabled")
        if policy.token == nil || policy.tokenBoot != boot || !isPFEnabled {
            if policy.tokenBoot == boot, let token = policy.token {
                // A global disable invalidates the previous enable reference on some
                // macOS versions. Release it best effort before taking a new one.
                _ = try? pf(["-X", token], requireSuccess: false)
            }
            let enabled = try pf(["-E"])
            let combined = enabled.output + "\n" + enabled.error
            guard let token = extractToken(combined) else {
                throw HelperFailure("PF was enabled but its ownership token was not returned. The block may be active; use recovery instructions before retrying.")
            }
            policy.token = token
            policy.tokenBoot = boot
            policy.stateFlushBoot = nil
            do { try savePolicy(policy) }
            catch {
                // Never accumulate enable references when protected storage fails.
                // Removing only the newly acquired reference preserves other users.
                _ = try? pf(["-X", token], requireSuccess: false)
                throw error
            }
        }
        if forceStateReset || policy.stateFlushBoot != boot {
            // This is GLOBAL, not anchor scoped. The UI explicitly discloses that
            // activating protection interrupts existing tracked connections.
            _ = try pf(["-F", "states"])
            policy.stateFlushBoot = boot
            try savePolicy(policy)
        }
        try verify(configuration: policy.configuration, interfaces: interfaces)
        return .init(enabled: true, verified: true, message: verifiedMessage(interfaces), tunnelInterfaces: interfaces)
    }

    private func verify(configuration: PFConfiguration, interfaces: [String]) throws {
        try preflight()
        guard try pf(["-s", "info"]).output.contains("Status: Enabled") else {
            throw HelperFailure("PF is disabled. The network block cannot be verified.")
        }
        let expected = try canonicalRules(PFPolicy.rules(configuration: configuration, trustedInterfaces: interfaces))
        let actual = PFPolicy.normalizedRules(try pf(["-a", PFPolicy.anchor, "-sr"]).output)
        guard actual == expected else { throw HelperFailure("The loaded firewall rules do not match the configured VPN policy.") }
        guard PFPolicy.normalizedRules(try pf(["-s", "states"]).output).isEmpty else {
            throw HelperFailure("PF contains connection states that could bypass the VPN rules. Disable and re-enable Latch to explicitly reset those connections.")
        }
    }

    private func canonicalRules(_ rules: String) throws -> [String] {
        let output = try pf(["-n", "-v", "-o", "none", "-a", PFPolicy.anchor, "-f", "-"], rules: rules).output
        let normalized = PFPolicy.normalizedRules(output)
        guard !normalized.isEmpty else { throw HelperFailure("PF returned no normalized rules for the VPN policy.") }
        return normalized
    }

    private func inspectAnchors(parent: String, depth: Int, visited: inout Set<String>) throws {
        guard depth <= 8, visited.count <= 64 else { throw HelperFailure("This PF anchor layout is too complex for safe automatic setup.") }
        let arguments = (parent.isEmpty ? [] : ["-a", parent]) + ["-s", "Anchors"]
        let output = try pf(arguments).output
        for line in output.split(separator: "\n") {
            var name = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if !parent.isEmpty, name.hasPrefix(parent + "/") { name = String(name.dropFirst(parent.count + 1)) }
            guard !name.isEmpty, name != ".", name != "..",
                  name.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,46,95].contains($0) }) else {
                throw HelperFailure("PF reported an unsupported anchor name.")
            }
            let path = parent.isEmpty ? name : parent + "/" + name
            guard visited.insert(path).inserted else { continue }
            if path != PFPolicy.anchor {
                try PFPolicy.validateForeignRules(try pf(["-a", path, "-sr"]).output)
                try validateTranslationOutput(try pf(["-a", path, "-sn"]).output)
            } else {
                // Our anchor contains only generated filter rules, never child hooks
                // or translations. Reject unexpected translation rules under it too.
                try validateTranslationOutput(try pf(["-a", path, "-sn"]).output)
            }
            try inspectAnchors(parent: path, depth: depth + 1, visited: &visited)
        }
    }

    private func validateTranslationOutput(_ text: String) throws {
        for line in PFPolicy.normalizedRules(text) {
            let allowed = ["nat-anchor", "rdr-anchor", "binat-anchor"].contains { keyword in
                line.hasPrefix(keyword + " \"") && line.hasSuffix("\" all")
            }
            guard allowed else {
                throw HelperFailure("Active NAT or redirection rules are incompatible with Latch's local guard. Disable Internet Sharing or the conflicting firewall before enabling it.")
            }
        }
    }

    private func trustedInterfaces(for configuration: PFConfiguration) throws -> [String] {
        let wanted = Set(configuration.tunnelAddresses.compactMap(IPAddress.init))
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { throw HelperFailure("Could not inspect network interfaces; tunnel traffic remains restricted.") }
        defer { freeifaddrs(first) }
        var result = Set<String>()
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            let value = current.pointee
            let name = String(cString: value.ifa_name)
            guard name.hasPrefix("utun"), !name.dropFirst(4).isEmpty, name.dropFirst(4).allSatisfy(\.isNumber),
                  value.ifa_flags & UInt32(IFF_UP) != 0, value.ifa_flags & UInt32(IFF_POINTOPOINT) != 0,
                  let address = value.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET) || address.pointee.sa_family == UInt8(AF_INET6) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let literal = String(cString: host).split(separator: "%", maxSplits: 1).first.map(String.init) ?? ""
            if let ip = IPAddress(literal), wanted.contains(ip) { result.insert(name) }
        }
        return result.sorted()
    }

    private func extractToken(_ output: String) -> String? {
        for line in output.split(separator: "\n") where line.lowercased().contains("token") {
            let pieces = line.split(separator: ":", maxSplits: 1)
            guard pieces.count == 2 else { continue }
            let value = pieces[1].trimmingCharacters(in: .whitespaces)
            if UInt64(value) != nil, !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }) { return value }
        }
        return nil
    }

    private func bootID() throws -> String {
        var value = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctlbyname("kern.boottime", &value, &size, nil, 0) == 0 else { throw HelperFailure("Could not identify this boot session; PF ownership cannot be verified.") }
        return "\(value.tv_sec).\(value.tv_usec)"
    }

    private func readPolicy() throws -> SavedPolicy? {
        guard let bytes = try SecureStore.read(stateName) else { return nil }
        let policy = try decoder.decode(SavedPolicy.self, from: bytes)
        _ = try policy.configuration.validated()
        if let token = policy.token {
            guard UInt64(token) != nil, token.utf8.allSatisfy({ (48...57).contains($0) }) else { throw HelperFailure("Stored PF ownership token is invalid.") }
        }
        return policy
    }

    private func savePolicy(_ policy: SavedPolicy) throws { try SecureStore.write(encoder.encode(policy), name: stateName) }

    @discardableResult
    private func publish(_ status: HelperStatus) throws -> HelperStatus {
        try SecureStore.write(encoder.encode(status), name: "status.json", mode: 0o644)
        return status
    }

    private func verifiedMessage(_ interfaces: [String]) -> String {
        interfaces.isEmpty ? "PF rules are loaded and verified. Connect to the configured WireGuard tunnel." : "PF rules are loaded and verified. Matching tunnel: \(interfaces.joined(separator: ", "))."
    }

    private func installHelper() throws {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        var path = [CChar](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&path, &size) == 0 else { throw HelperFailure("Could not locate the helper executable.") }
        let sourcePath = String(cString: path)
        let source = open(sourcePath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0 else { throw HelperFailure("Could not read the authorized helper executable.") }
        defer { close(source) }
        var info = stat()
        guard fstat(source, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size > 0, info.st_size <= 50_000_000 else { throw HelperFailure("The helper executable is invalid.") }
        let reader = FileHandle(fileDescriptor: source, closeOnDealloc: false)
        var contents = Data()
        while let chunk = try reader.read(upToCount: 8192), !chunk.isEmpty {
            guard contents.count + chunk.count <= 50_000_000 else { throw HelperFailure("The helper executable grew unexpectedly.") }
            contents.append(chunk)
        }
        guard contents.count == info.st_size else { throw HelperFailure("The helper executable changed while being installed.") }
        try SecureStore.write(contents, name: "dev.ensurevpn.helper", directory: "/Library/PrivilegedHelperTools", mode: 0o755)
        let plist: [String: Any] = [
            "Label": "dev.ensurevpn.helper",
            "ProgramArguments": [SecureStore.helperPath, "watch"],
            "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 5,
            "ProcessType": "Background", "UserName": "root",
            "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try SecureStore.write(data, name: "dev.ensurevpn.helper.plist", directory: "/Library/LaunchDaemons", mode: 0o644)
    }

    private func startWatcher() throws {
        let existing = try CommandRunner.run("/bin/launchctl", ["print", service], requireSuccess: false)
        if existing.status == 0 {
            _ = try CommandRunner.run("/bin/launchctl", ["kickstart", "-k", service])
        } else {
            _ = try CommandRunner.run("/bin/launchctl", ["bootstrap", "system", SecureStore.launchPath])
        }
    }
}
