import AppKit
import Darwin

/// Each policy change gets administrator authorization. Only the helper runs as root.
@MainActor
final class FilterController: ObservableObject {
    @Published private(set) var isEnabled = false
    @Published private(set) var isVerified = false
    @Published private(set) var isBusy = false
    @Published private(set) var isStatusUncertain = false
    @Published private(set) var helperInstalled = false
    @Published private(set) var tunnelInterfaces: [String] = []
    @Published var message: String?
    static let statusPath = "/Library/Application Support/EnsureVPN/status.json"
    private var timer: Timer?

    init() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    struct Status: Decodable {
        let schemaVersion: Int
        let enabled: Bool
        let verified: Bool
        let updatedAt: Double
        let message: String
        let tunnelInterfaces: [String]
        let helperVersion: Int
    }

    func refresh() {
        guard !isBusy else { return }
        do {
            let directory = URL(fileURLWithPath: Self.statusPath).deletingLastPathComponent().path
            guard FileManager.default.fileExists(atPath: directory) else {
                helperInstalled = FileManager.default.isExecutableFile(atPath: "/Library/PrivilegedHelperTools/dev.ensurevpn.helper")
                isVerified = false
                isStatusUncertain = isEnabled || helperInstalled
                if isStatusUncertain { message = "Helper status is missing. Use Restore normal networking in Preferences & recovery if the block is still active." }
                return
            }
            guard Self.isRootOwned(directory, directory: true), Self.isRootOwned(Self.statusPath, directory: false) else {
                throw Self.failure("Helper status has unexpected permissions. Protection cannot be verified.")
            }
            let status = try JSONDecoder().decode(Status.self, from: Data(contentsOf: URL(fileURLWithPath: Self.statusPath)))
            guard status.schemaVersion == 1, status.helperVersion == 1 else {
                throw Self.failure("Update the local helper to read its status.")
            }
            helperInstalled = true
            isEnabled = status.enabled
            let age = Date().timeIntervalSince1970 - status.updatedAt
            isStatusUncertain = age < -2 || age >= 8
            isVerified = status.verified && age >= -2 && age < 8
            tunnelInterfaces = status.tunnelInterfaces
            if isStatusUncertain {
                message = "Helper status is stale. Whether the block is on or off cannot be verified. Check the firewall or use Restore normal networking below."
            } else if status.enabled && !isVerified {
                message = status.message
            } else {
                let normalOff = status.message == "The network block is off." || status.message.hasSuffix("'s block is off. Normal network routing and other firewall settings apply.")
                message = status.enabled || normalOff || status.verified ? nil : status.message
            }
        } catch {
            isVerified = false
            isStatusUncertain = true
            message = error.localizedDescription
        }
    }

    func enable(addresses: [String], endpoints: [ServerException]) {
        guard !isBusy, !isEnabled, !addresses.isEmpty, !endpoints.isEmpty else { return }
        do {
            let data = try JSONSerialization.data(withJSONObject: [
                "tunnelAddresses": addresses,
                "endpoints": endpoints.map { ["address": $0.address, "port": $0.port] as [String: Any] }
            ])
            perform(command: "enable", argument: data.base64EncodedString())
        } catch { message = error.localizedDescription }
    }

    func disable() { perform(command: "disable") }
    func checkWithAdministrator() { perform(command: "status") }

    private func perform(command: String, argument: String? = nil) {
        guard !isBusy else { return }
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/EnsureVPNHelper")
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            message = "The PF helper is missing. Rebuild the app with scripts/build-app.sh."
            return
        }
        isBusy = true
        message = nil
        Task {
            do {
                let output = try await Task.detached(priority: .userInitiated) {
                    let parts = [helper.path, command] + (argument.map { [$0] } ?? [])
                    let shellCommand = parts.map(Self.shellQuote).joined(separator: " ")
                    let script = "do shell script " + Self.appleScriptQuote(shellCommand) + " with administrator privileges"
                    let process = Process()
                    process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                    process.arguments = ["-e", script]
                    let pipe = Pipe()
                    process.standardOutput = pipe
                    process.standardError = pipe
                    try process.run()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    let output = String(decoding: data, as: UTF8.self)
                    guard process.terminationStatus == 0 else {
                        var detail = String(output.prefix(3000)).trimmingCharacters(in: .whitespacesAndNewlines)
                        if let start = output.firstIndex(of: "{"), let end = output.lastIndex(of: "}"),
                           start <= end,
                           let response = try? JSONDecoder().decode(Status.self, from: Data(output[start...end].utf8)) {
                            // Errors may follow a partial apply: use only the message,
                            // never the error envelope's enabled/verified fields.
                            detail = response.message
                        }
                        throw Self.failure(output.contains("(-128)")
                            ? "Administrator approval was cancelled. The previous setting was kept."
                            : detail)
                    }
                    return output
                }.value
                isBusy = false
                refresh()
                if let line = output.split(whereSeparator: \.isNewline).last,
                   let status = try? JSONDecoder().decode(Status.self, from: Data(line.utf8)),
                   !status.verified { message = status.message }
            } catch {
                isBusy = false
                refresh()
                message = error.localizedDescription
            }
        }
    }

    nonisolated private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    nonisolated private static func appleScriptQuote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    nonisolated private static func failure(_ message: String) -> NSError {
        NSError(domain: "EnsureVPN", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    nonisolated private static func isRootOwned(_ path: String, directory: Bool) -> Bool {
        var info = stat()
        guard lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & 0o022 == 0 else { return false }
        return info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) && (directory || info.st_size <= 65_536)
    }
}
