import Foundation
import Darwin

func printStatus(_ status: HelperStatus) {
    if let data = try? JSONEncoder().encode(status), let string = String(data: data, encoding: .utf8) { print(string) }
}

guard CommandLine.arguments.count >= 2 else {
    fputs("Usage: EnsureVPNHelper enable BASE64_JSON | disable | status | preflight | watch\n", stderr)
    exit(64)
}
guard geteuid() == 0 else {
    printStatus(.init(enabled: false, verified: false, message: "Administrator authorization is required. Use the menu bar app or run this helper with sudo."))
    exit(77)
}
umask(0o077)
signal(SIGPIPE, SIG_IGN)
let engine = HelperEngine()
do {
    switch CommandLine.arguments[1] {
    case "enable":
        guard CommandLine.arguments.count == 3 else { throw HelperFailure("Enable requires one encoded VPN policy.") }
        printStatus(try engine.enable(CommandLine.arguments[2]))
    case "disable":
        guard CommandLine.arguments.count == 2 else { throw HelperFailure("Unexpected arguments.") }
        printStatus(try engine.disable())
    case "status":
        guard CommandLine.arguments.count == 2 else { throw HelperFailure("Unexpected arguments.") }
        printStatus(try engine.status())
    case "preflight":
        guard CommandLine.arguments.count == 2 else { throw HelperFailure("Unexpected arguments.") }
        try engine.preflight()
        printStatus(.init(enabled: false, verified: false, message: "PF compatibility checks passed. No network configuration was changed."))
    case "watch":
        guard CommandLine.arguments.count == 2 else { throw HelperFailure("Unexpected arguments.") }
        engine.watch()
    default: throw HelperFailure("Unknown helper command.")
    }
} catch {
    printStatus(.init(enabled: false, verified: false, message: error.localizedDescription))
    exit(1)
}
