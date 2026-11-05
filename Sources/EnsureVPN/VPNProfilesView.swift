import SwiftUI
import EnsureVPNCore

struct VPNProfilesView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("VPN profiles (\(model.profiles.count))").fontWeight(.semibold)
                Spacer()
                Button(action: model.importProfile) {
                    Label(model.importing ? "Adding…" : "Add", systemImage: "plus")
                }
                .controlSize(.small)
                .disabled(!model.canEditProfiles)
                .help("Add one or more WireGuard configurations")
            }
            Text("Every saved profile is allowed. Switch between them in WireGuard while Always-on VPN stays on.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(model.profiles) { profile in
                VPNProfileRow(profile: profile,
                              observation: model.profileObservations[profile.id] ?? .init(),
                              canRemove: model.canEditProfiles,
                              remove: { model.removeProfile(id: profile.id) })
                if profile.id != model.profiles.last?.id { Divider() }
            }

            if !model.canEditProfiles && !model.importing {
                Text("Turn off Always-on VPN before adding or removing profiles.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            if let summary = model.importSummary {
                Text(summary).font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Text("Loopback, DHCP, and local IPv6 discovery also remain available. All other connections must use a saved tunnel.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }.font(.system(size: 12))
    }
}

private struct VPNProfileRow: View {
    let profile: SavedVPNProfile
    let observation: TunnelObservation
    let canRemove: Bool
    let remove: () -> Void
    @State private var expanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Tunnel addresses").foregroundStyle(.secondary)
                Text(profile.tunnelAddresses.joined(separator: ", "))
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                Text("Server exceptions").foregroundStyle(.secondary)
                ForEach(profile.endpoints, id: \.self) { endpoint in
                    Text("\(endpoint.address.description) · UDP \(endpoint.port)")
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
                Button("Remove profile", role: .destructive, action: remove)
                    .disabled(!canRemove)
                    .accessibilityLabel("Remove \(profile.name) profile")
            }.font(.system(size: 11)).padding(.top, 8)
        } label: {
            VStack(alignment: .leading, spacing: 3) {
                Text(profile.name).fontWeight(.medium).lineLimit(1).truncationMode(.middle)
                Text(observation.isPresent
                     ? "Interface match: \(observation.interfaces.joined(separator: ", "))"
                     : "\(profile.endpoints.count) \(profile.endpoints.count == 1 ? "server exception" : "server exceptions")")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
    }
}
