import AppKit

/// Two compact rows occupy fixed drawing positions, without padded text gaps.
/// A template image preserves the menu bar's native tint and pressed appearance.
@MainActor
enum MenuBarRates {
    static let itemLength: CGFloat = 94
    static let imageSize = NSSize(width: 84, height: 20)
    static let font = NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .medium)

    static func image(symbol: String, download: Double, upload: Double, available: Bool) -> NSImage {
        let shield = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(.init(pointSize: 16, weight: .regular))
        let down = "↓ " + formatted(download, available: available)
        let up = "↑ " + formatted(upload, available: available)
        let attributes: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: NSColor.black]
        let image = NSImage(size: imageSize, flipped: false) { _ in
            shield?.draw(in: NSRect(x: 0, y: 2, width: 16, height: 16))
            (down as NSString).draw(at: NSPoint(x: 23, y: 9), withAttributes: attributes)
            (up as NSString).draw(at: NSPoint(x: 23, y: -1), withAttributes: attributes)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Download \(formatted(download, available: available)), upload \(formatted(upload, available: available))"
        return image
    }

    static func formatted(_ rate: Double, available: Bool) -> String {
        guard available, rate.isFinite else { return "—" }
        let units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
        var amount = max(0, rate)
        var unit = 0
        // Promote before rounding would display 1000 in the smaller unit.
        while amount >= 999.5 && unit < units.count - 1 {
            amount /= 1000
            unit += 1
        }
        if amount >= 999.5 { return "999+ TB/s" }
        let number = unit > 0 && amount < 10 ? String(format: "%.1f", amount) : String(format: "%.0f", amount)
        return "\(number) \(units[unit])"
    }
}
