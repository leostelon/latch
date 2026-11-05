// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Latch",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "EnsureVPN", targets: ["EnsureVPN"]),
        .executable(name: "EnsureVPNFilter", targets: ["EnsureVPNFilter"]),
        .executable(name: "EnsureVPNHelper", targets: ["EnsureVPNHelper"]),
        .executable(name: "EnsureVPNPFChecks", targets: ["EnsureVPNPFChecks"]),
        .executable(name: "EnsureVPNChecks", targets: ["EnsureVPNChecks"])
    ],
    targets: [
        .target(name: "EnsureVPNCore"),
        .executableTarget(name: "EnsureVPN", dependencies: ["EnsureVPNCore"]),
        .executableTarget(name: "EnsureVPNFilter", dependencies: ["EnsureVPNCore"]),
        .executableTarget(name: "EnsureVPNHelper", dependencies: ["EnsureVPNCore"]),
        .executableTarget(name: "EnsureVPNPFChecks", dependencies: ["EnsureVPNCore"], path: "Tests/EnsureVPNPFChecks"),
        .executableTarget(name: "EnsureVPNChecks", dependencies: ["EnsureVPNCore"], path: "Tests/EnsureVPNChecks"),
        .testTarget(name: "EnsureVPNCoreTests", dependencies: ["EnsureVPNCore"])
    ],
    swiftLanguageModes: [.v5]
)
