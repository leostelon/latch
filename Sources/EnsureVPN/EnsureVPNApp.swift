import AppKit
import Combine
import SwiftUI
import UserNotifications

@main
struct EnsureVPNApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene { Settings { EmptyView() } }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private var statusItem: NSStatusItem!
    private let popover = NSPopover()
    private var model: AppModel!
    private var subscription: AnyCancellable?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        model = AppModel()
        UNUserNotificationCenter.current().delegate = self
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.target = self
            button.action = #selector(togglePopover)
            button.setAccessibilityLabel("Latch")
        }
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: PopoverView(model: model))
        updateStatusItem()
        subscription = model.objectWillChange.sink { [weak self] _ in
            DispatchQueue.main.async { self?.updateStatusItem() }
        }
        if CommandLine.arguments.contains("--preview") {
            renderPreview()
        } else if !UserDefaults.standard.bool(forKey: "hasLaunched") {
            UserDefaults.standard.set(true, forKey: "hasLaunched")
            DispatchQueue.main.async { self.togglePopover() }
        }
    }

    private func updateStatusItem() {
        let image = NSImage(systemSymbolName: model.symbol, accessibilityDescription: "Latch")
        image?.isTemplate = true
        statusItem.button?.image = image
        if model.showMenuBarSpeeds {
            let download = model.traffic.available ? TrafficRates.formatted(model.traffic.download) : "—"
            let upload = model.traffic.available ? TrafficRates.formatted(model.traffic.upload) : "—"
            statusItem.button?.title = " ↓ \(download)  ↑ \(upload)"
            statusItem.button?.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
            statusItem.button?.imagePosition = .imageLeading
        } else { statusItem.button?.title = "" }
        statusItem.button?.toolTip = "Latch: \(model.statusTitle). Always-on VPN \(model.filter.isEnabled ? "on" : "off")."
    }

    @objc private func togglePopover() {
        if popover.isShown { popover.performClose(nil) }
        else if let button = statusItem.button {
            model.checkTunnel()
            model.filter.refresh()
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    // An offscreen native render used for visual QA; it never activates a filter.
    private func renderPreview() {
        let host = NSHostingView(rootView: PopoverView(model: model))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 370, height: 600),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        let size = host.fittingSize
        window.setContentSize(size)
        host.frame = NSRect(origin: .zero, size: size)
        host.layoutSubtreeIfNeeded()
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.2) {
            if let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
                host.cacheDisplay(in: host.bounds, to: bitmap)
                if let png = bitmap.representation(using: .png, properties: [:]) {
                    let path = ProcessInfo.processInfo.environment["ENSURE_VPN_PREVIEW"] ?? "/tmp/ensure-vpn-preview.png"
                    try? png.write(to: URL(fileURLWithPath: path))
                }
            }
            NSApp.terminate(nil)
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}
