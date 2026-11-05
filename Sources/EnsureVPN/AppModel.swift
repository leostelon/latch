import AppKit
import Combine
import EnsureVPNCore
import ServiceManagement
import UniformTypeIdentifiers
import UserNotifications

struct SavedProfile: Codable {
    let name: String
    let tunnelAddresses: [String]
    let endpoints: [ServerException]
    let importedAt: Date
    let usesHostnameEndpoint: Bool?
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var profile: SavedProfile?
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

    init() {
        if let data = UserDefaults.standard.data(forKey: "wireGuardProfile") {
            profile = try? JSONDecoder().decode(SavedProfile.self, from: data)
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
        if profile == nil { return "No VPN. No connection." }
        if filter.isEnabled { return observation.isPresent ? "WireGuard interface detected" : "Connect to WireGuard" }
        return observation.isPresent ? "WireGuard interface detected" : "WireGuard not detected"
    }

    var statusDescription: String {
        if filter.isStatusUncertain { return "The helper’s status is unavailable. Check the firewall before relying on protection." }
        if filter.isEnabled && !filter.isVerified { return "The guard is switched on, but its firewall rules could not be verified. Check the message below." }
        if profile == nil { return "Keep outgoing traffic inside your WireGuard tunnel, with a guard in your menu bar." }
        if filter.isEnabled {
            return observation.isPresent
                ? "Always-on VPN is on. Direct connections are blocked and your tunnel interface is present."
                : "Always-on VPN is on. Direct connections are blocked. Open WireGuard to get online."
        }
        return "Always-on VPN is off. Apps can connect normally, with or without a VPN."
    }

    func checkTunnel() {
        let newValue = TunnelObservation.read(addresses: profile?.tunnelAddresses ?? [])
        if observation.isPresent && !newValue.isPresent && notifyOnDisconnect,
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
        guard !filter.isEnabled, !filter.isBusy, !importing else { return }
        let panel = NSOpenPanel()
        panel.title = "Import a WireGuard configuration"
        panel.message = "Only tunnel addresses and server endpoints are saved. Keys are discarded."
        panel.allowedContentTypes = [.init(filenameExtension: "conf") ?? .plainText]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        importing = true
        error = nil
        Task {
            do {
                let imported = try await Task.detached(priority: .userInitiated) { () throws -> SavedProfile in
                    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size <= 1_048_576 else {
                        throw NSError(domain: "EnsureVPN", code: 3, userInfo: [NSLocalizedDescriptionKey: "Choose a WireGuard configuration smaller than 1 MB."])
                    }
                    let config = try WireGuardConfiguration.parse(String(contentsOf: url, encoding: .utf8))
                    var servers = Set<ServerException>()
                    for endpoint in config.endpoints {
                        servers.formUnion(try EndpointResolver.resolve(host: endpoint.host, port: Int(endpoint.port)))
                    }
                    guard servers.count <= 128 else {
                        throw NSError(domain: "EnsureVPN", code: 4, userInfo: [NSLocalizedDescriptionKey: "This configuration resolves to more than 128 server addresses. Choose a smaller set of WireGuard peers."])
                    }
                    return SavedProfile(name: url.deletingPathExtension().lastPathComponent,
                                        tunnelAddresses: config.tunnelAddresses,
                                        endpoints: servers.sorted { ($0.address, $0.port) < ($1.address, $1.port) },
                                        importedAt: Date(),
                                        usesHostnameEndpoint: config.endpoints.contains { IPAddress($0.host) == nil })
                }.value
                let encoded = try JSONEncoder().encode(imported)
                UserDefaults.standard.set(encoded, forKey: "wireGuardProfile")
                profile = imported
                checkTunnel()
            } catch { self.error = error.localizedDescription }
            importing = false
        }
    }

    func enable() {
        guard let profile else { return }
        filter.enable(addresses: profile.tunnelAddresses, endpoints: profile.endpoints)
    }

    func openWireGuard() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.wireguard.macos") else {
            error = "Install WireGuard for macOS, then activate the tunnel matching your imported configuration."
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
