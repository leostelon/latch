import SwiftUI

struct PopoverView: View {
    @ObservedObject var model: AppModel
    @State private var showEnableConfirmation = false
    @State private var showPreferences = false

    private var guardLabel: String {
        if model.filter.isBusy { return "Applying…" }
        if model.filter.isStatusUncertain { return "Status unknown" }
        if !model.filter.isEnabled { return "Off" }
        return model.filter.isVerified ? "On · rules verified" : "On · needs attention"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "shield.lefthalf.filled").font(.system(size: 17, weight: .semibold)).foregroundStyle(.tint)
                Text("Latch").font(.system(size: 15, weight: .semibold))
                Spacer()
                Text("WireGuard").font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
            }.padding(.horizontal, 20).padding(.vertical, 16)
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 10) {
                        Image(systemName: model.profiles.isEmpty ? "lock.shield" : model.symbol)
                            .font(.system(size: 32, weight: .light))
                            .foregroundStyle(model.filter.isVerified && model.filter.isEnabled ? Color.accentColor : Color.secondary)
                            .accessibilityHidden(true)
                        Text(model.statusTitle).font(.system(size: 22, weight: .semibold))
                            .fixedSize(horizontal: false, vertical: true)
                        Text(model.statusDescription).font(.system(size: 13)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true).lineSpacing(3)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Always-on VPN").font(.system(size: 14, weight: .semibold))
                                Text(guardLabel).font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Toggle("Always-on VPN", isOn: .init(get: { model.filter.isEnabled }, set: { value in
                                if value { showEnableConfirmation = true }
                                else { model.filter.disable() }
                            })).labelsHidden().toggleStyle(.switch)
                                .disabled(model.filter.isBusy || model.importing || (!model.filter.isEnabled && (model.profiles.isEmpty || model.filter.isStatusUncertain)))
                        }
                        Text(model.profiles.isEmpty
                             ? "Add a WireGuard profile to enable this switch."
                             : "On blocks connections outside your VPN. Off allows normal networking. Administrator approval is required to change it.")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(12).background(.quaternary, in: RoundedRectangle(cornerRadius: 8))

                    trafficView

                    if !model.profiles.isEmpty {
                        VPNProfilesView(model: model)

                        if model.profiles.contains(where: { $0.usesHostnameEndpoint == true }) {
                            Label("For reliable reconnection without direct DNS, use a numeric server IP in WireGuard, then export and reimport its configuration.", systemImage: "info.circle")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }

                        Button(action: model.openWireGuard) { Text("Open WireGuard").frame(maxWidth: .infinity) }
                            .buttonStyle(.borderedProminent).controlSize(.large)
                        if model.filter.isEnabled {
                            Text("The guard stays on when you quit this app. It reapplies after restart, but protection before the helper starts is not guaranteed.")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    } else {
                        VStack(alignment: .leading, spacing: 10) {
                            Button(action: model.importProfile) {
                                Label(model.importing ? "Importing…" : "Add WireGuard profiles", systemImage: "plus")
                                    .frame(maxWidth: .infinity)
                            }.buttonStyle(.borderedProminent).controlSize(.large).disabled(!model.canEditProfiles)
                            Text("Choose one or more .conf files. Private keys are never saved. No Apple developer account is needed.")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                    }

                    if let message = model.error ?? model.filter.message {
                        Label(message, systemImage: "exclamationmark.circle")
                            .font(.system(size: 12)).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    DisclosureGroup("Preferences & recovery", isExpanded: $showPreferences) {
                        VStack(alignment: .leading, spacing: 12) {
                            Toggle("Show speeds in menu bar", isOn: .init(get: { model.showMenuBarSpeeds }, set: model.setShowMenuBarSpeeds))
                            Toggle("Open at login", isOn: .init(get: { model.launchAtLogin }, set: model.setLogin))
                            Toggle("Notify when the tunnel disconnects", isOn: .init(get: { model.notifyOnDisconnect }, set: model.setNotifications))
                            Button("Check firewall with administrator…", action: model.filter.checkWithAdministrator)
                                .disabled(model.filter.isBusy)
                            Button("Restore normal networking…", action: model.filter.disable)
                                .disabled(model.filter.isBusy)
                            Button("Setup & recovery instructions", action: model.openBuildInstructions)
                        }.toggleStyle(.checkbox).padding(.top, 10)
                    }.font(.system(size: 12))
                }.padding(20)
            }.frame(maxHeight: 650)

            Divider()
            HStack {
                Text(model.filter.isStatusUncertain ? "Firewall status unknown" : (model.filter.isEnabled ? "Always-on VPN on" : "Always-on VPN off"))
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }.buttonStyle(.plain)
                    .font(.system(size: 12)).keyboardShortcut("q")
            }.padding(.horizontal, 20).padding(.vertical, 12)
        }
        .frame(width: 370)
        .background(Color(nsColor: .windowBackgroundColor))
        .alert("Turn on Always-on VPN?", isPresented: $showEnableConfirmation) {
            Button("Turn on", action: model.enable)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Connections outside your saved WireGuard tunnels will be blocked in both directions, except their server traffic and basic network setup. Existing network sessions will reset once to close bypasses. macOS will ask for an administrator password to run the local helper. You can switch between saved tunnels while the guard stays on.")
        }
    }

    private var trafficView: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(model.traffic.isTunnel ? "Tunnel traffic" : "Network traffic")
                Spacer()
                Text(model.traffic.interface ?? "No interface").foregroundStyle(.secondary)
            }.font(.system(size: 11))
            HStack(spacing: 0) {
                rateColumn("Download", symbol: "arrow.down", rate: model.traffic.download)
                Spacer()
                rateColumn("Upload", symbol: "arrow.up", rate: model.traffic.upload)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func rateColumn(_ title: String, symbol: String, rate: Double) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: symbol).font(.system(size: 11)).foregroundStyle(.secondary)
            Text(model.traffic.available ? TrafficRates.formatted(rate) : "—")
                .font(.system(size: 19, weight: .medium, design: .rounded)).monospacedDigit()
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
