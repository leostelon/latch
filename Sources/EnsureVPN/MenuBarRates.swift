import AppKit

/// Fixed-width ASCII fields keep the shield, arrows, and neighboring menu items
/// stationary when digit counts or units change. Use a fully monospaced font:
/// monospaced digits alone do not give B/s and MB/s equal character advances.
@MainActor
enum MenuBarRates {
    static let font = NSFont.monospacedSystemFont(ofSize: 10, weight: .regular)
    private static let fieldLength = 11 // Includes the rounding case "1000.0 MB/s".

    static let itemLength: CGFloat = {
        let widest = title(download: 999_999_999, upload: 999_999_999, available: true)
        return ceil((widest as NSString).size(withAttributes: [.font: font]).width)
            + NSStatusBar.system.thickness + 12
    }()

    static func title(download: Double, upload: Double, available: Bool) -> String {
        " ↓ \(field(download, available: available))  ↑ \(field(upload, available: available))"
    }

    private static func field(_ rate: Double, available: Bool) -> String {
        let value: String
        if !available || !rate.isFinite { value = "--" }
        else if rate >= 1_000_000_000_000 { value = "999+ GB/s" }
        else { value = TrafficRates.formatted(rate) }
        return String(repeating: " ", count: max(0, fieldLength - value.count)) + value
    }
}
