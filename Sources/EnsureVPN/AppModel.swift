import AppKit
import Combine
import EnsureVPNCore
import ServiceManagement
import UniformTypeIdentifiers
import UserNotifications

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var profiles: [SavedVPNProfile] = []
    @Published private(set) var profileObservations: [UUID: TunnelObservation] = [:]
    @Published private(set) var importSummary: String?
    @Published private(set) var observation = TunnelObservation()
    @Published private(set) var importing = false
    @Published var error: String?
    @Published var notifyOnDisconnect = UserDefaults.standard.bool(forKey: "notifyOnDisconnect")
    @Published private(set) var launchAtLogin = SMAppService.mainApp.status == .enabled
    @Published private(set) var traffic = TrafficRates()
    @Published var showMenuBarSpeeds = UserDefaults.standard.object(forKey: "showMenuBarSpeeds") as? Bool ?? true
    let filter = FilterController()
    private var timer: Timer?
    private var cancellables = Set<AnyCancellable>()
    private var lastNotification = Date.distantPast
    private var trafficMonitor = TrafficMonitor()
    private static let profilesKey = "wireGuardProfiles.v1"

    private var canChangePolicy: Bool { !filter.isEnabled && !filter.isBusy && !filter.isStatusUncertain }
    var canEditProfiles: Bool { canChangePolicy && !importing }

    init(previewProfiles: [SavedVPNProfile]? = nil) {
        if let previewProfiles {
            profiles = previewProfiles
        } else {
            do {
                let defaults = UserDefaults.standard
                let current = defaults.data(forKey: Self.profilesKey)
                profiles = try SavedVPNProfiles.decode(current: current, legacy: defaults.data(forKey: "wireGuardProfile"))
                if current == nil {
                    defaults.set(try SavedVPNProfiles.encode(profiles), forKey: Self.profilesKey)
                    defaults.removeObject(forKey: "wireGuardProfile")
                }
            } catch {
                self.error = "Saved profiles could not be loaded: \(error.localizedDescription)"
            }
        }
        filter.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &cancellables)
        checkTunnel()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.checkTunnel()
                self.traffic = self.trafficMonitor.sample(tunnelInterfaces: self.observation.interfaces)
            }
        }
    }

    var symbol: String {
        if filter.isStatusUncertain || (filter.isEnabled && !filter.isVerified) { return "exclamationmark.shield" }
        if filter.isEnabled { return observation.isPresent ? "shield.lefthalf.filled" : "shield.slash" }
        return "shield"
    }

    var statusTitle: String {
        if filter.isStatusUncertain || (filter.isEnabled && !filter.isVerified) { return "Always-on VPN needs attention" }
        if profiles.isEmpty { return "No VPN. No connection." }
        if filter.isEnabled { return observation.isPresent ? "WireGuard interface detected" : "Connect to WireGuard" }
        return observation.isPresent ? "WireGuard interface detected" : "WireGuard not detected"
    }

    var statusDescription: String {
        if filter.isStatusUncertain { return "The helper’s status is unavailable. Check the firewall before relying on protection." }
        if filter.isEnabled && !filter.isVerified { return "The guard is switched on, but its firewall rules could not be verified. Check the message below." }
        if profiles.isEmpty { return "Keep outgoing traffic inside your WireGuard tunnels, with a guard in your menu bar." }
        if filter.isEnabled {
            return observation.isPresent
                ? "Always-on VPN is on. Direct connections are blocked and a saved tunnel interface is present."
                : "Always-on VPN is on. Direct connections are blocked. Open WireGuard to get online."
        }
        return "Always-on VPN is off. Apps can connect normally, with or without a VPN."
    }

    func checkTunnel(notifyOnChange: Bool = true) {
        let inventory = TunnelObservation.inventory()
        let matches = Dictionary(uniqueKeysWithValues: profiles.map {
            ($0.id, TunnelObservation.read(addresses: $0.tunnelAddresses, inventory: inventory))
        })
        let newValue = TunnelObservation(interfaces: Set(matches.values.flatMap(\.interfaces)).sorted())
        if matches != profileObservations { profileObservations = matches }
        if notifyOnChange && observation.isPresent && !newValue.isPresent && notifyOnDisconnect,
           Date().timeIntervalSince(lastNotification) > 30 {
            lastNotification = Date()
            let content = UNMutableNotificationContent()
            content.title = "Reconnect to WireGuard"
            content.body = filter.isEnabled && filter.isVerified
                ? "Your tunnel is no longer detected. Always-on VPN is blocking direct connections."
                : "Your tunnel is no longer detected. Check Always-on VPN before relying on network protection."
            UNUserNotificationCenter.current().add(.init(identifier: "vpn-disconnected", content: content, trigger: nil))
        }
        if newValue != observation { observation = newValue }
    }

    func importProfile() {
        guard canEditProfiles else { return }
        let panel = NSOpenPanel()
        panel.title = "Add WireGuard profiles"
        panel.message = "Choose one or more .conf files. Only tunnel addresses and server endpoints are saved; keys are discarded."
        panel.allowedContentTypes = [.init(filenameExtension: "conf") ?? .plainText]
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        let urls = panel.urls
        guard urls.count <= 64 else {
            error = "Choose no more than 64 WireGuard profiles at once."
            return
        }
        importing = true
        error = nil
        importSummary = nil
        Task {
            do {
                let imported = try await Task.detached(priority: .userInitiated) { () throws -> [SavedVPNProfile] in
                    try urls.map { url in
                        do {
                            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                            guard size <= 1_048_576 else {
                                throw NSError(domain: "Latch", code: 3, userInfo: [NSLocalizedDescriptionKey: "Choose a configuration smaller than 1 MB."])
                            }
                            let config = try WireGuardConfiguration.parse(String(contentsOf: url, encoding: .utf8))
                            var servers = Set<ResolvedEndpoint>()
                            for endpoint in config.endpoints {
                                for resolved in try EndpointResolver.resolve(host: endpoint.host, port: Int(endpoint.port)) {
                                    guard let address = IPAddress(resolved.address), let port = UInt16(exactly: resolved.port) else {
                                        throw PFPolicyError.invalidEndpoint
                                    }
                                    servers.insert(.init(address: address, port: port))
                                }
                            }
                            return try SavedVPNProfile(name: url.deletingPathExtension().lastPathComponent,
                                                       tunnelAddresses: config.tunnelAddresses,
                                                       endpoints: Array(servers), importedAt: Date(),
                                                       usesHostnameEndpoint: config.endpoints.contains { IPAddress($0.host) == nil })
                        } catch {
                            throw NSError(domain: "Latch", code: 4, userInfo: [NSLocalizedDescriptionKey: "\(url.lastPathComponent): \(error.localizedDescription)"])
                        }
                    }
                }.value
                guard canChangePolicy else {
                    throw NSError(domain: "Latch", code: 5, userInfo: [NSLocalizedDescriptionKey: "Turn off Always-on VPN and verify its status before changing saved profiles."])
                }
                let combined = try SavedVPNProfiles.appending(imported: imported, to: profiles)
                let added = combined.count - profiles.count
                try saveProfiles(combined)
                importSummary = added == 0 ? "These profiles are already saved." : "Added \(added) \(added == 1 ? "profile" : "profiles"). All saved VPN servers are included in the exceptions."
            } catch { self.error = error.localizedDescription }
            importing = false
        }
    }

    func enable() {
        guard !profiles.isEmpty, !importing, !filter.isStatusUncertain else { return }
        do {
            let combined = try SavedVPNProfiles.combinedConfiguration(profiles)
            filter.enable(addresses: combined.tunnelAddresses,
                          endpoints: combined.endpoints.map { ServerException(address: $0.address.description, port: Int($0.port)) })
        } catch { self.error = error.localizedDescription }
    }

    func removeProfile(id: UUID) {
        guard canEditProfiles else { return }
        do {
            try saveProfiles(profiles.filter { $0.id != id })
            importSummary = nil
            error = nil
        } catch { self.error = error.localizedDescription }
    }

    private func saveProfiles(_ values: [SavedVPNProfile]) throws {
        let encoded = try SavedVPNProfiles.encode(values)
        UserDefaults.standard.set(encoded, forKey: Self.profilesKey)
        profiles = values
        checkTunnel(notifyOnChange: false)
    }

    func openWireGuard() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.wireguard.macos") else {
            error = "Install WireGuard for macOS, then activate a tunnel matching one of your saved profiles."
            return
        }
        NSWorkspace.shared.openApplication(at: url, configuration: .init()) { _, error in
            if let error { Task { @MainActor in self.error = error.localizedDescription } }
        }
    }

    func setLogin(_ value: Bool) {
        do {
            if value { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            launchAtLogin = SMAppService.mainApp.status == .enabled
            if value && !launchAtLogin { error = "Allow Latch in Login Items in System Settings." }
        } catch { self.error = error.localizedDescription }
    }

    func setNotifications(_ value: Bool) {
        guard value else {
            notifyOnDisconnect = false
            UserDefaults.standard.set(false, forKey: "notifyOnDisconnect")
            return
        }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            Task { @MainActor in
                self.notifyOnDisconnect = granted
                UserDefaults.standard.set(granted, forKey: "notifyOnDisconnect")
                if !granted { self.error = error?.localizedDescription ?? "Allow notifications for Latch in System Settings." }
            }
        }
    }

    func openSystemSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") { NSWorkspace.shared.open(url) }
    }

    func setShowMenuBarSpeeds(_ value: Bool) {
        showMenuBarSpeeds = value
        UserDefaults.standard.set(value, forKey: "showMenuBarSpeeds")
    }

    func openBuildInstructions() {
        if let url = Bundle.main.url(forResource: "README", withExtension: "md") { NSWorkspace.shared.open(url) }
    }
}
