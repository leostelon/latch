import Foundation

/// Public routing information for a saved WireGuard connection; never VPN keys.
public struct SavedVPNProfile: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public let name: String
    public let tunnelAddresses: [String]
    public let endpoints: [ResolvedEndpoint]
    public let importedAt: Date
    public let usesHostnameEndpoint: Bool?

    public init(id: UUID = UUID(), name: String, tunnelAddresses: [String],
                endpoints: [ResolvedEndpoint], importedAt: Date = Date(),
                usesHostnameEndpoint: Bool? = nil) throws {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.utf8.count <= 256 else { throw SavedVPNProfilesError.invalidName }
        guard importedAt.timeIntervalSinceReferenceDate.isFinite else { throw SavedVPNProfilesError.invalidDate }
        let configuration = try PFConfiguration(tunnelAddresses: tunnelAddresses, endpoints: endpoints)
        self.id = id
        self.name = name
        self.tunnelAddresses = configuration.tunnelAddresses
        self.endpoints = configuration.endpoints
        self.importedAt = importedAt
        self.usesHostnameEndpoint = usesHostnameEndpoint
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(id: values.decode(UUID.self, forKey: .id),
                      name: values.decode(String.self, forKey: .name),
                      tunnelAddresses: values.decode([String].self, forKey: .tunnelAddresses),
                      endpoints: values.decode([ResolvedEndpoint].self, forKey: .endpoints),
                      importedAt: values.decode(Date.self, forKey: .importedAt),
                      usesHostnameEndpoint: values.decodeIfPresent(Bool.self, forKey: .usesHostnameEndpoint))
    }
}

public enum SavedVPNProfilesError: Error, LocalizedError, Equatable {
    case tooLarge, tooManyProfiles, duplicateIdentity, invalidName, invalidDate

    public var errorDescription: String? {
        switch self {
        case .tooLarge: return "The saved VPN profile data is too large to load safely."
        case .tooManyProfiles: return "Save up to 64 VPN connections. Remove an existing connection before adding another."
        case .duplicateIdentity: return "Saved VPN connections contain duplicate identifiers. Reimport the affected connections."
        case .invalidName: return "A VPN connection needs a name of at most 256 UTF-8 bytes."
        case .invalidDate: return "The VPN connection has an invalid import date."
        }
    }
}

public enum SavedVPNProfiles {
    private static let maximumBytes = 2_097_152
    private static let maximumProfiles = 64

    /// A present current-format value is authoritative, including an empty array.
    /// Invalid current data must not silently resurrect an older single profile.
    public static func decode(current: Data?, legacy: Data?) throws -> [SavedVPNProfile] {
        let profiles: [SavedVPNProfile]
        if let current {
            guard current.count <= maximumBytes else { throw SavedVPNProfilesError.tooLarge }
            profiles = try JSONDecoder().decode([SavedVPNProfile].self, from: current)
        } else if let legacy {
            guard legacy.count <= maximumBytes else { throw SavedVPNProfilesError.tooLarge }
            let old = try JSONDecoder().decode(LegacyProfile.self, from: legacy)
            profiles = [try SavedVPNProfile(name: old.name, tunnelAddresses: old.tunnelAddresses,
                                            endpoints: old.endpoints, importedAt: old.importedAt,
                                            usesHostnameEndpoint: old.usesHostnameEndpoint)]
        } else {
            profiles = []
        }
        try validate(profiles)
        return profiles
    }

    public static func encode(_ profiles: [SavedVPNProfile]) throws -> Data {
        try validate(profiles)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(profiles)
        guard data.count <= maximumBytes else { throw SavedVPNProfilesError.tooLarge }
        return data
    }

    /// All saved profiles are allowed. Switching WireGuard connections does not
    /// require turning off the guard or broadening its exact endpoint exceptions.
    public static func combinedConfiguration(_ profiles: [SavedVPNProfile]) throws -> PFConfiguration {
        try validate(profiles)
        return try aggregate(profiles)
    }

    /// Importing an equivalent configuration keeps its existing name and UUID.
    /// Different configurations may share a display name without overwriting one another.
    public static func appending(imported: [SavedVPNProfile], to existing: [SavedVPNProfile]) throws -> [SavedVPNProfile] {
        try validate(existing)
        guard imported.count <= maximumProfiles else { throw SavedVPNProfilesError.tooManyProfiles }
        var result = existing
        for profile in imported {
            let alreadySaved = result.contains {
                $0.tunnelAddresses == profile.tunnelAddresses && $0.endpoints == profile.endpoints
            }
            if !alreadySaved { result.append(profile) }
        }
        try validate(result)
        return result
    }

    private static func validate(_ profiles: [SavedVPNProfile]) throws {
        guard profiles.count <= maximumProfiles else { throw SavedVPNProfilesError.tooManyProfiles }
        guard Set(profiles.map(\.id)).count == profiles.count else { throw SavedVPNProfilesError.duplicateIdentity }
        if !profiles.isEmpty { _ = try aggregate(profiles) }
    }

    private static func aggregate(_ profiles: [SavedVPNProfile]) throws -> PFConfiguration {
        // Enforce the helper's limits on unique values, not the number of repeated
        // addresses shared by multiple otherwise distinct connections.
        let addresses = Set(profiles.flatMap(\.tunnelAddresses)).sorted()
        let endpoints = Array(Set(profiles.flatMap(\.endpoints)))
        return try PFConfiguration(tunnelAddresses: addresses, endpoints: endpoints)
    }

    private struct LegacyProfile: Decodable {
        let name: String
        let tunnelAddresses: [String]
        let endpoints: [ResolvedEndpoint]
        let importedAt: Date
        let usesHostnameEndpoint: Bool?
    }
}
