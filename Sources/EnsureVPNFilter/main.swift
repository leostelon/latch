import Foundation
import NetworkExtension

// launchd starts this executable after macOS activates the signed system extension.
NEProvider.startSystemExtensionMode()
dispatchMain()
